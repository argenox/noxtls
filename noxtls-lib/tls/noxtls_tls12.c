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
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_tls12.h"
#include "noxtls_tls_kdf.h"
#include "noxtls_tls_common.h"
#include "noxtls_tls_key_exchange.h"
#include "drbg/noxtls_drbg.h"
#include "certs/noxtls_x509.h"
#include "pkc/rsa/noxtls_rsa.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "mdigest/sha1/noxtls_sha1.h"
#include "mdigest/md5/noxtls_md5.h"
#include "noxtls_tls_noxsight.h"

/**
 * @brief Initialize TLS 1.2 context
 */
noxtls_return_t tls12_context_init_with_version(tls12_context_t *ctx, tls_role_t role, uint16_t version)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    /* For TLS 1.0/1.1 use plain TLS context init; for TLS/DTLS 1.2 use dtls_context_init */
    if(version == TLS_VERSION_1_0 || version == TLS_VERSION_1_1) {
        memset(&ctx->base, 0, sizeof(dtls_context_t));
        if(noxtls_tls_context_init(&ctx->base.base, role, version) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    } else {
        if(dtls_context_init(&ctx->base, role, version) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    
    ctx->record_workspace = NULL;
    ctx->handshake_workspace = NULL;
    if(version == TLS_VERSION_1_2) {
        ctx->record_workspace = (uint8_t*)noxtls_malloc(TLS_MAX_RECORD_SIZE + TLS_RECORD_WORKSPACE_OVERHEAD);
        if(ctx->record_workspace == NULL) {
            dtls_context_free(&ctx->base);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        ctx->handshake_workspace = (uint8_t*)noxtls_malloc(TLS_HANDSHAKE_WORKSPACE_SIZE);
        if(ctx->handshake_workspace == NULL) {
            noxtls_free(ctx->record_workspace);
            ctx->record_workspace = NULL;
            dtls_context_free(&ctx->base);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
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
    ctx->server_cert_parsed = NULL;  /* Initialize to NULL */
    ctx->server_private_rsa = NULL;
    ctx->crypto_provider = NULL;
    ctx->server_private_key_handle = NULL;
    ctx->ecdhe_ctx = NULL;
    ctx->dhe_ctx = NULL;
    ctx->handshake_messages = NULL;
    ctx->handshake_messages_len = 0;
    ctx->server_name = NULL;
    ctx->server_name_len = 0;
    ctx->previous_verify_data_len = 0;
    ctx->renegotiation_in_progress = 0;
    ctx->server_use_rpk = 0;
    ctx->server_certificate_type = TLS_CERT_TYPE_X509;
    ctx->client_certificate_type = TLS_CERT_TYPE_X509;
    ctx->server_cert_is_rpk = 0;
    ctx->client_accept_server_rpk = 0;
    ctx->client_offer_client_rpk = 0;
    ctx->max_fragment_length_code = 0;
    ctx->max_record_payload = 0;

    /* Zero extensions so tls12_context_free can safely call noxtls_tls_extensions_free */
    memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
    memset(&ctx->server_extensions, 0, sizeof(ctx->server_extensions));
    
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t tls12_context_init(tls12_context_t *ctx, tls_role_t role)
{
    return tls12_context_init_with_version(ctx, role, TLS_VERSION_1_2);
}

noxtls_return_t dtls12_context_init(tls12_context_t *ctx, tls_role_t role)
{
    noxtls_return_t rc = tls12_context_init_with_version(ctx, role, TLS_VERSION_1_2);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    ctx->base.base.version = DTLS_VERSION_1_2;
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
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256:
            /* AES-128 cipher suites use secp256r1 */
            *named_group = TLS_NAMED_GROUP_SECP256R1;
            return NOXTLS_RETURN_SUCCESS;
            
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
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
        memcpy(premaster, shared, copy_len);
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

    rc = dtls_generate_cookie(&ctx->base, client_hello, client_hello_len, cookie, &cookie_len);
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
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
            return NOXTLS_HASH_SHA_384;
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
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
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_CBC_SHA256:
            return NOXTLS_HASH_SHA_256;
        case TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA:
            return NOXTLS_HASH_SHA1;
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
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_GCM_SHA256:
            *named_group = TLS_NAMED_GROUP_FFDHE2048;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_GCM_SHA384:
            *named_group = TLS_NAMED_GROUP_FFDHE3072;
            return NOXTLS_RETURN_SUCCESS;
        default:
            return NOXTLS_RETURN_FAILED;
    }
}

/**
 * @brief Free TLS 1.2 context
 */
noxtls_return_t tls12_context_free(tls12_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->server_cert) {
        free(ctx->server_cert);
        ctx->server_cert = NULL;
    }
    
    if(ctx->server_cert_parsed) {
        noxtls_x509_certificate_free((x509_certificate_t*)ctx->server_cert_parsed);
        free(ctx->server_cert_parsed);
        ctx->server_cert_parsed = NULL;
    }
    
    if(ctx->handshake_messages) {
        free(ctx->handshake_messages);
        ctx->handshake_messages = NULL;
    }
    
    /* Free ECDHE context if it exists */
    if(ctx->ecdhe_ctx) {
        tls_ecdhe_context_free((tls_ecdhe_context_t*)ctx->ecdhe_ctx);
        free(ctx->ecdhe_ctx);
        ctx->ecdhe_ctx = NULL;
    }
    /* Free DHE context if it exists */
    if(ctx->dhe_ctx) {
        tls_dhe_context_free((tls_dhe_context_t*)ctx->dhe_ctx);
        free(ctx->dhe_ctx);
        ctx->dhe_ctx = NULL;
    }
    
    /* Free extensions */
    noxtls_tls_extensions_free(&ctx->client_extensions);
    noxtls_tls_extensions_free(&ctx->server_extensions);
    
    if(ctx->record_workspace) {
        noxtls_free(ctx->record_workspace);
        ctx->record_workspace = NULL;
    }
    if(ctx->handshake_workspace) {
        memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        noxtls_free(ctx->handshake_workspace);
        ctx->handshake_workspace = NULL;
    }
    dtls_context_free(&ctx->base);
    
    return NOXTLS_RETURN_SUCCESS;
}

void tls12_set_server_private_rsa(tls12_context_t *ctx, void *rsa_key)
{
    if(ctx != NULL) {
        ctx->server_private_rsa = rsa_key;
    }
}

void tls12_set_crypto_provider_server(tls12_context_t *ctx, const noxtls_crypto_provider_t *provider, noxtls_crypto_key_handle_t server_key_handle)
{
    if(ctx != NULL) {
        ctx->crypto_provider = provider;
        ctx->server_private_key_handle = server_key_handle;
    }
}

void tls12_set_server_use_rpk(tls12_context_t *ctx, int use_rpk)
{
    if(ctx != NULL) {
        ctx->server_use_rpk = (use_rpk != 0) ? 1 : 0;
    }
}

void tls12_set_client_accept_server_rpk(tls12_context_t *ctx, int accept)
{
    if(ctx != NULL) {
        ctx->client_accept_server_rpk = (accept != 0) ? 1 : 0;
    }
}

void tls12_set_client_offer_client_rpk(tls12_context_t *ctx, int offer)
{
    if(ctx != NULL) {
        ctx->client_offer_client_rpk = (offer != 0) ? 1 : 0;
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

void tls12_set_max_fragment_length(tls12_context_t *ctx, uint8_t code)
{
    if(ctx != NULL) {
        if(code >= 1 && code <= 4) {
            ctx->max_fragment_length_code = code;
        } else {
            ctx->max_fragment_length_code = 0;
        }
    }
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
    
    if(ctx == NULL || premaster_secret == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(premaster_secret_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Determine hash algorithm based on cipher suite */
    hash_algo = tls12_get_prf_hash(ctx->cipher_suite);
    
    /* Build seed: client_random + server_random */
    memcpy(seed, ctx->client_random, 32);
    memcpy(seed + 32, ctx->server_random, 32);
    
    noxtls_debug_printf("[TLS12_DEBUG] master_secret: premaster_len=%u cipher=0x%04X\n",
                          premaster_secret_len, ctx->cipher_suite);
    fflush(stdout);
    /* Generate master secret using PRF (TLS 1.0/1.1 use MD5/SHA-1 PRF) */
    const char *label = "master secret";
    size_t label_len = strlen(label);
    if(label_len > UINT32_MAX) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->base.base.version <= TLS_VERSION_1_1) {
        rc = tls10_prf(premaster_secret, premaster_secret_len, (const uint8_t*)label, (uint32_t)label_len,
                       seed, 64, ctx->master_secret, 48);
    } else {
        rc = tls12_prf(premaster_secret, premaster_secret_len, (const uint8_t*)label, (uint32_t)label_len,
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
    uint32_t mac_key_len, enc_key_len, iv_len;
    
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
        case TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA:
            hash_algo = NOXTLS_HASH_SHA_256;  /* PRF; MAC is SHA-1 */
            mac_key_len = 20;
            enc_key_len = 24;
            iv_len = 8;
            key_block_len = (mac_key_len << 1) + (enc_key_len << 1) + (iv_len << 1);
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA:
            hash_algo = NOXTLS_HASH_SHA_256;  /* SHA-1 for MAC, but use SHA-256 PRF */
            mac_key_len = 20;  /* SHA-1 MAC key */
            enc_key_len = (ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA) ? 16 : 32;
            iv_len = 16;
            key_block_len = (mac_key_len << 1) + (enc_key_len << 1) + (iv_len << 1);
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384:
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
               ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_CBC_SHA384 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384) {
                hash_algo = NOXTLS_HASH_SHA_384;
                mac_key_len = 48;  /* SHA-384 MAC key */
            }
            enc_key_len = (ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_ARIA_128_CBC_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_CBC_SHA256) ? 16 : 32;
            if(ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384) {
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

    printf("[TLS12_DEBUG] derive_keys: suite=0x%04X hash=%u mac=%lu enc=%lu iv=%lu key_block=%lu\n",
           ctx->cipher_suite, (unsigned)hash_algo, (unsigned long)mac_key_len, (unsigned long)enc_key_len, (unsigned long)iv_len, (unsigned long)key_block_len);
    fflush(stdout);
    
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
        printf("[TLS12_DEBUG] derive_keys: prf rc=%d\n", rc);
        fflush(stdout);
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
 * @brief Append handshake message to handshake messages buffer
 */
static noxtls_return_t tls12_append_handshake_message(tls12_context_t *ctx, const uint8_t *data, uint32_t len)
{
    if(ctx == NULL || data == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Reallocate buffer to accommodate new message */
    uint8_t *new_buffer = (uint8_t*)realloc(ctx->handshake_messages, ctx->handshake_messages_len + len);
    if(new_buffer == NULL && len > 0) {
        return NOXTLS_RETURN_FAILED;
    }
    
    ctx->handshake_messages = new_buffer;
    memcpy(ctx->handshake_messages + ctx->handshake_messages_len, data, len);
    ctx->handshake_messages_len += len;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Compute handshake hash for Finished message
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
        noxtls_sha_ctx_t md5_ctx, sha_ctx;
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
noxtls_return_t tls12_send_client_hello(tls12_context_t *ctx)
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
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256,
        TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256,
        TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256,
        TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA
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
    
    /* Build Client Hello message */
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

#ifndef TLS_EXTENSION_EC_POINT_FORMATS
#define TLS_EXTENSION_EC_POINT_FORMATS 11
#endif

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
                ext_buf[ext_len++] = 0x00;
                ext_buf[ext_len++] = TLS_EXTENSION_EC_POINT_FORMATS;
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
    
    /* Update handshake message length (skip extensions for TLS 1.0/1.1) */
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

/**
 * @brief TLS 1.2 Client: Receive Server Hello
 */
noxtls_return_t tls12_recv_server_hello(tls12_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_server_hello: Starting...\n");
    rc = noxtls_tls_recv_record(&ctx->base.base, &record);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(record.length > 0 && record.data == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_server_hello: Record received - type=%u, length=%u\n",
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
        rc = tls12_send_client_hello(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        return tls12_recv_server_hello(ctx);
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
                } else if(etype == TLS_EXTENSION_MAX_FRAGMENT_LENGTH && elen >= 1) {
                    uint8_t mfl = record.data[offset];
                    if(mfl >= 1 && mfl <= 4) {
                        ctx->max_fragment_length_code = mfl;
                        ctx->max_record_payload = tls12_mfl_code_to_payload(mfl);
                    }
                }
                offset += elen;
            }
        }
    }
    (void)offset;
    
    /* Append to handshake messages (for Finished verify_data computation) */
    tls12_append_handshake_message(ctx, record.data, record.length);
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_server_hello: Completed\n");
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_HANDSHAKE, NOXSIGHT_SEVERITY_INFO,
                    NOXTLS_EVT_SERVER_HELLO_RECV, ctx->cipher_suite, record.length);
    
    if(record.data) free(record.data);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Client: Receive Certificate
 */
noxtls_return_t tls12_recv_certificate(tls12_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    uint32_t cert_list_len;
    uint32_t cert_len;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_certificate: Starting...\n");
    rc = noxtls_tls_recv_record(&ctx->base.base, &record);
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_certificate: noxtls_tls_recv_record returned %d\n", rc);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_IO, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_INTERNAL_ERROR, NOXTLS_EVT_CERTIFICATE_RECV, rc);
        return rc;
    }
    if(record.length > 0 && record.data == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_certificate: Record received - type=%u, length=%u\n", record.type, record.length);
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_certificate: hs_type=0x%02X\n",
                          record.length > 0 ? record.data[0] : 0);
    
    if(record.type != TLS_RECORD_HANDSHAKE || record.length < 6) {
        noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_certificate: Invalid record type or length\n");
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_CERT_PARSE_FAIL, record.type, record.length);
        if(record.data) noxtls_free(record.data);
        return NOXTLS_RETURN_TLS_ERROR;
    }
    
    if(record.data[0] != TLS_HANDSHAKE_CERTIFICATE) {
        noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_certificate: Not a certificate message (got %u)\n", record.data[0]);
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_CERT_PARSE_FAIL, record.data[0], record.length);
        if(record.data) noxtls_free(record.data);
        return NOXTLS_RETURN_TLS_ERROR;
    }
    tls12_inc_recv_seq(ctx);
    
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_certificate: Parsing certificate message...\n");
    
    /* Parse Certificate message */
    /* Certificate list length at offset 1-3 */
    cert_list_len = (record.data[1] << 16) | (record.data[2] << 8) | record.data[3];
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_certificate: Certificate list length: %u\n", cert_list_len);
    
    {
        uint32_t record_len = record.length;
        if(cert_list_len < 3 || cert_list_len > record_len - 4) {
            noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_certificate: Invalid certificate list length\n");
            if(record.data) noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
    }
    
    /* First certificate length at offset 4-6 */
    cert_len = (record.data[4] << 16) | (record.data[5] << 8) | record.data[6];
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_certificate: First certificate length: %u\n", cert_len);
    
    if(cert_len > cert_list_len - 3) {
        noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_certificate: Certificate length exceeds list length\n");
        if(record.data) noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_certificate: Allocating %u bytes for server certificate...\n", cert_len);
    
    /* Store server certificate */
    if(ctx->server_cert) {
        noxtls_free(ctx->server_cert);
    }
    ctx->server_cert = (uint8_t*)noxtls_malloc(cert_len);
    if(ctx->server_cert == NULL) {
        noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_certificate: Memory allocation failed\n");
        if(record.data) noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    memcpy(ctx->server_cert, record.data + 7, cert_len);
    ctx->server_cert_len = cert_len;
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_certificate: Certificate stored (%u bytes)\n", cert_len);
    fflush(stdout);

    /* RFC 7250: If server chose Raw Public Key, payload is SubjectPublicKeyInfo; do not parse as X.509. Verify out-of-band. */
    if(ctx->server_certificate_type == TLS_CERT_TYPE_RAW_PUBLIC_KEY) {
        ctx->server_cert_is_rpk = 1;
        ctx->server_cert_parsed = NULL;  /* No X.509 structure; application uses server_cert (SPKI) for verification */
    } else {
        /* Parse the certificate as X.509 */
        noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_certificate: Checking if server_cert_parsed needs cleanup...\n");
        noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_certificate: server_cert_parsed = %p\n", ctx->server_cert_parsed);
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
                        if(record.data) noxtls_free(record.data);
                        return hr;
                    }
                }
            } else {
                NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                                NOXTLS_EVT_CERT_PARSE_FAIL, ctx->server_cert_len, cert_list_len);
                noxtls_x509_certificate_free(parsed_cert);
                noxtls_free(parsed_cert);
                if(record.data) noxtls_free(record.data);
                return parse_rc;
            }
        }
    }
    
    /* Append to handshake messages (for Finished verify_data computation) */
    tls12_append_handshake_message(ctx, record.data, record.length);
    
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_certificate: Freeing record data...\n");
    fflush(stdout);
    if(record.data) noxtls_free(record.data);
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_certificate: Record data freed\n");
    fflush(stdout);
    
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_certificate: Completed successfully\n");
    fflush(stdout);
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_INFO,
                    NOXTLS_EVT_CERTIFICATE_RECV, cert_len, cert_list_len);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Client: Receive Server Key Exchange
 */
noxtls_return_t tls12_recv_server_key_exchange(tls12_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_server_key_exchange: Starting...\n");
    rc = noxtls_tls_recv_record(&ctx->base.base, &record);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(record.length > 0 && record.data == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_server_key_exchange: Record received - type=%u, length=%u\n",
                          record.type, record.length);
    
    if(record.type != TLS_RECORD_HANDSHAKE) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_server_key_exchange: hs_type=0x%02X\n",
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
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384);
    int is_dhe_kex = (ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384 ||
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
        rc = tls_dhe_context_init(dhe_ctx, named_group);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(dhe_ctx);
            if(record.data) free(record.data);
            return rc;
        }
        ctx->dhe_ctx = dhe_ctx;
        rc = tls12_dhe_recv_server_key_exchange(ctx, dhe_ctx, record.data, record.length);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            tls_dhe_context_free(dhe_ctx);
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
        /* ECDHE: Parse Server Key Exchange message first to get server's chosen curve */
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
        noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_server_key_exchange: curve_type=0x%02X\n", curve_type);
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
        noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_server_key_exchange: named_curve=0x%04X\n", named_curve);
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
            /* Create or replace ECDHE context with the curve from the server's message */
            if(ecdhe_ctx != NULL) {
                tls_ecdhe_context_free(ecdhe_ctx);
                free(ecdhe_ctx);
                ctx->ecdhe_ctx = NULL;
            }
            noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_server_key_exchange: init ecdhe ctx (group=0x%04X)\n", named_curve);
            fflush(stdout);
            ecdhe_ctx = (tls_ecdhe_context_t*)malloc(sizeof(tls_ecdhe_context_t));
            if(ecdhe_ctx == NULL) {
                if(record.data) free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            rc = tls_ecdhe_context_init(ecdhe_ctx, named_curve);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                free(ecdhe_ctx);
                if(record.data) free(record.data);
                return rc;
            }
            noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_server_key_exchange: tls_ecdhe_generate_ephemeral_key...\n");
            fflush(stdout);
            rc = tls_ecdhe_generate_ephemeral_key(ecdhe_ctx);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                tls_ecdhe_context_free(ecdhe_ctx);
                free(ecdhe_ctx);
                if(record.data) free(record.data);
                return rc;
            }
            noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_server_key_exchange: local ephemeral key ready\n");
            fflush(stdout);
            ctx->ecdhe_ctx = ecdhe_ctx;
        }
        
        /* Public key length */
        noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_server_key_exchange: reading public_key_len at offset=%u\n", msg_offset);
        fflush(stdout);
        if(msg_offset >= record.length) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        public_key_len = record.data[msg_offset++];
        noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_server_key_exchange: public_key_len=%u\n",
                              public_key_len);
        fflush(stdout);
        
        /* Public key */
        if(msg_offset + public_key_len > record.length) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        
        /* Decode peer's public key */
        noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_server_key_exchange: Decoding peer public key...\n");
        fflush(stdout);
        rc = tls_decode_ecc_point_uncompressed(record.data + msg_offset, public_key_len, &peer_public_key, ecdhe_ctx->curve_type);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(record.data) free(record.data);
            return rc;
        }
        
        /* Compute shared secret */
        noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_server_key_exchange: Computing shared secret...\n");
        fflush(stdout);
        rc = tls_ecdhe_compute_shared_secret(ecdhe_ctx, &peer_public_key);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(record.data) free(record.data);
            return rc;
        }
        noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_server_key_exchange: Shared secret computed\n");
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
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_server_key_exchange: Completed\n");
    
    if(record.data) free(record.data);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Client: Receive Server Hello Done
 */
noxtls_return_t tls12_recv_server_hello_done(tls12_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_server_hello_done: Starting...\n");
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
    noxtls_debug_printf("[TLS12_DEBUG] tls12_recv_server_hello_done: Record received - type=%u, length=%u, hs_type=0x%02X\n",
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
noxtls_return_t tls12_send_client_key_exchange(tls12_context_t *ctx)
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
    
    /* Build Client Key Exchange message */
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
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384);
    
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
            rsa_key_size_t key_size = (key_bytes == 128) ? RSA_1024_BIT : (key_bytes == 256) ? RSA_2048_BIT :
                                      (key_bytes == 384) ? RSA_3072_BIT : (key_bytes == 512) ? RSA_4096_BIT : (rsa_key_size_t)0;
            if(key_bytes != 128 && key_bytes != 256 && key_bytes != 384 && key_bytes != 512) {
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
            
            rc = tls_ecdhe_context_init(ecdhe_ctx, named_group);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                free(ecdhe_ctx);
                if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return rc;
            }
            
            /* Generate ephemeral key pair */
            rc = tls_ecdhe_generate_ephemeral_key(ecdhe_ctx);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                tls_ecdhe_context_free(ecdhe_ctx);
                free(ecdhe_ctx);
                if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return rc;
            }
            
            ctx->ecdhe_ctx = ecdhe_ctx;
        }
        
        /* Get encoded public key */
        uint8_t public_key_encoded[133];  /* Max: 1 + 2*66 for P-521 */
        uint32_t public_key_len = sizeof(public_key_encoded);
        rc = tls_ecdhe_get_public_key_encoded(ecdhe_ctx, public_key_encoded, &public_key_len);
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
    
    /* Update handshake message length */
    uint32_t handshake_len = offset - 4;
    client_key_exchange[1] = (handshake_len >> 16) & 0xFF;
    client_key_exchange[2] = (handshake_len >> 8) & 0xFF;
    client_key_exchange[3] = handshake_len & 0xFF;
    
    /* Append to handshake messages (for Finished verify_data computation) */
    tls12_append_handshake_message(ctx, client_key_exchange, offset);
    
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
noxtls_return_t tls12_send_change_cipher_spec(tls12_context_t *ctx)
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
noxtls_return_t tls12_send_finished(tls12_context_t *ctx)
{
    uint8_t finished[TLS_MAX_SECRET_LEN];
    uint32_t offset = 0;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Build Finished message */
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
    
    /* After Change Cipher Spec, Finished message must be encrypted */
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
    
    /* Encrypt the Finished message before sending */
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
        noxtls_debug_printf("ERROR: Failed to encrypt Finished message: %d\n", rc);
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
noxtls_return_t tls12_recv_change_cipher_spec(tls12_context_t *ctx)
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
    
    if(record.type != TLS_RECORD_CHANGE_CIPHER_SPEC || record.length != 1) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    if(record.data[0] != TLS_RECORD_CCS_PAYLOAD) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    tls12_inc_recv_seq(ctx);
    /* Reset sequence number for new cipher state (receive side). */
    if(ctx->base.base.role == TLS_ROLE_CLIENT) {
        ctx->server_seq_num = 0;
    } else {
        ctx->client_seq_num = 0;
    }
    tls12_dtls_on_recv_ccs(ctx);
    
    if(record.data) free(record.data);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Client: Receive Finished
 */
noxtls_return_t tls12_recv_finished(tls12_context_t *ctx)
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
    int used_decrypt = 0;
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
        used_decrypt = 1;
    }

    if(finished_len != 16 || finished_msg[0] != TLS_HANDSHAKE_FINISHED) {
        noxtls_debug_printf("[TLS12_DEBUG] recv_finished: bad decrypted header type=%u len=%u\n",
                              finished_msg[0], finished_len);
        if(decrypted != ctx->record_workspace) {
            noxtls_free(decrypted);
        }
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Verify finished message */
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
    /* Compare verify_data (starts at offset 4 in Finished message) */
    if(memcmp(finished_msg + 4, computed_verify_data, 12) != 0) {
        noxtls_debug_printf("ERROR: Finished message verification failed!\n");
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
    /* Finished consumes a sequence number only if record was unencrypted. */
    if(!used_decrypt) {
        tls12_inc_recv_seq(ctx);
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Server: Send HelloRequest to ask client to renegotiate (RFC 5746).
 */
noxtls_return_t tls12_send_hello_request(tls12_context_t *ctx)
{
    uint8_t hello_request[4];
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
    return noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, hello_request, sizeof(hello_request));
}

/**
 * @brief TLS 1.2 Client: Connect
 */
noxtls_return_t tls12_connect(tls12_context_t *ctx)
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
    printf("[TLS12_DEBUG] tls12_connect: send_client_hello...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_SEND_CH);
    rc = tls12_send_client_hello(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] tls12_connect: send_client_hello rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_CH, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_CH, rc);
    
    /* Receive Server Hello */
    printf("[TLS12_DEBUG] tls12_connect: recv_server_hello...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_RECV_SH);
    rc = tls12_recv_server_hello(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] tls12_connect: recv_server_hello rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_SH, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_SH, rc);
    
    /* Receive Certificate */
    printf("[TLS12_DEBUG] tls12_connect: recv_certificate...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_VERIFY_CERT);
    rc = tls12_recv_certificate(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] tls12_connect: recv_certificate rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_VERIFY_CERT, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_VERIFY_CERT, rc);
    
    /* Receive Server Key Exchange */
    printf("[TLS12_DEBUG] tls12_connect: recv_server_key_exchange...\n");
    rc = tls12_recv_server_key_exchange(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] tls12_connect: recv_server_key_exchange rc=%d\n", rc);
        return rc;
    }
    
    /* Receive Server Hello Done */
    printf("[TLS12_DEBUG] tls12_connect: recv_server_hello_done...\n");
    rc = tls12_recv_server_hello_done(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] tls12_connect: recv_server_hello_done rc=%d\n", rc);
        return rc;
    }
    
    /* Send Client Key Exchange */
    printf("[TLS12_DEBUG] tls12_connect: send_client_key_exchange...\n");
    rc = tls12_send_client_key_exchange(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] tls12_connect: send_client_key_exchange rc=%d\n", rc);
        return rc;
    }
    
    /* Compute master secret from premaster secret */
    printf("[TLS12_DEBUG] tls12_connect: compute_master_secret...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_KEY_SCHEDULE);
    if(ctx->dhe_ctx != NULL) {
        tls_dhe_context_t *dhe_ctx = (tls_dhe_context_t*)ctx->dhe_ctx;
        rc = tls12_compute_master_secret(ctx, dhe_ctx->premaster_secret, dhe_ctx->premaster_secret_len);
    } else {
        rc = tls12_compute_master_secret(ctx, ctx->premaster_secret, ctx->premaster_secret_len);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] tls12_connect: compute_master_secret rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_KEY_SCHEDULE, rc);
        return rc;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 1u, ctx->cipher_suite);
    
    /* Derive keys from master secret */
    printf("[TLS12_DEBUG] tls12_connect: derive_keys...\n");
    rc = tls12_derive_keys(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] tls12_connect: derive_keys rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_KEY_SCHEDULE, rc);
        return rc;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 2u, ctx->cipher_suite);
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_KEY_SCHEDULE, rc);
    
    /* Send Change Cipher Spec */
    printf("[TLS12_DEBUG] tls12_connect: send_change_cipher_spec...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_SEND_FINISHED);
    rc = tls12_send_change_cipher_spec(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] tls12_connect: send_change_cipher_spec rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_FINISHED, rc);
        return rc;
    }
    
    /* Send Finished */
    printf("[TLS12_DEBUG] tls12_connect: send_finished...\n");
    rc = tls12_send_finished(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] tls12_connect: send_finished rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_FINISHED, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_FINISHED, rc);
    
    /* Receive Change Cipher Spec */
    printf("[TLS12_DEBUG] tls12_connect: recv_change_cipher_spec...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_RECV_FINISHED);
    rc = tls12_recv_change_cipher_spec(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] tls12_connect: recv_change_cipher_spec rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_FINISHED, rc);
        return rc;
    }
    
    /* Receive Finished */
    printf("[TLS12_DEBUG] tls12_connect: recv_finished...\n");
    rc = tls12_recv_finished(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] tls12_connect: recv_finished rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_FINISHED, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_FINISHED, rc);
    
    ctx->base.base.state = TLS_STATE_CONNECTED;
    dtls_mark_validated(&ctx->base);
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_CONNECTED);
    
    return NOXTLS_RETURN_SUCCESS;
}

/* Parse ClientHello from buffer (used for server renegotiation when ClientHello received in tls12_recv). */
static noxtls_return_t tls12_parse_client_hello_from_buf(tls12_context_t *ctx, const uint8_t *buf, uint32_t len)
{
    uint32_t offset;
    uint8_t session_id_len;
    uint16_t cipher_suites_len;
    uint8_t compression_methods_len;
    uint16_t supported_10_11[] = {
        TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA,
        TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA,
        TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA,
    };
    uint16_t supported_12[] = {
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256,
        TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA,
    };
    uint16_t *supported_suites = (ctx->base.base.version <= TLS_VERSION_1_1) ? supported_10_11 : supported_12;
    uint32_t num_supported = (ctx->base.base.version <= TLS_VERSION_1_1)
        ? (sizeof(supported_10_11) / sizeof(supported_10_11[0]))
        : (sizeof(supported_12) / sizeof(supported_12[0]));
    if(ctx == NULL || buf == NULL || len < 38) {
        return NOXTLS_RETURN_FAILED;
    }
    if(buf[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_tls_extensions_free(&ctx->client_extensions);
    memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
    offset = 4;
    offset += 2; /* version */
    memcpy(ctx->client_random, buf + offset, TLS_RANDOM_SIZE);
    offset += TLS_RANDOM_SIZE;
    session_id_len = buf[offset++];
    offset += session_id_len;
    if(tls12_is_dtls(ctx) && offset < len) {
        uint8_t cookie_len = buf[offset++];
        if(offset + cookie_len > len) { return NOXTLS_RETURN_FAILED; }
        offset += cookie_len;
    }
    if(offset + 2 + 1 > len) { return NOXTLS_RETURN_FAILED; }
    cipher_suites_len = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;
    if(offset + cipher_suites_len + 1 > len) { return NOXTLS_RETURN_FAILED; }
    ctx->cipher_suite = 0;
    for(uint32_t i = 0; i < (uint32_t)cipher_suites_len >> 1 && i < num_supported; i++) {
        uint16_t suite = (buf[offset + i*2] << 8) | buf[offset + i*2 + 1];
        for(uint32_t j = 0; j < num_supported; j++) {
            if(suite == supported_suites[j]) { ctx->cipher_suite = suite; break; }
        }
        if(ctx->cipher_suite != 0) break;
    }
    if(ctx->cipher_suite == 0) { return NOXTLS_RETURN_FAILED; }
    offset += cipher_suites_len;
    compression_methods_len = buf[offset++];
    offset += compression_methods_len;
    if(offset + 2 <= len) {
        uint16_t extensions_len = (buf[offset] << 8) | buf[offset + 1];
        offset += 2;
        if(offset + extensions_len <= len && extensions_len > 0) {
            noxtls_tls_parse_extensions(buf + offset, extensions_len, &ctx->client_extensions);
        }
    }
    tls12_append_handshake_message(ctx, buf, len);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Server: Receive Client Hello
 */
noxtls_return_t tls12_recv_client_hello(tls12_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    uint32_t offset;
    uint16_t version;
    uint8_t session_id_len;
    uint16_t cipher_suites_len;
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
        if(ctx->base.base.pending_client_hello_len > UINT16_MAX) {
            return NOXTLS_RETURN_FAILED;
        }
        record.length = (uint16_t)ctx->base.base.pending_client_hello_len;
        record.data = (uint8_t*)malloc(record.length);
        if(record.length > 0 && record.data == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(record.data, ctx->base.base.pending_client_hello, record.length);
        use_pending = 1;
    } else {
        rc = noxtls_tls_recv_record(&ctx->base.base, &record);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    if(record.length > 0 && record.data == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    
    if(record.type != TLS_RECORD_HANDSHAKE || record.length < 38) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    if(record.data[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    if(!use_pending) {
        tls12_inc_recv_seq(ctx);
    }
    
    offset = 4;  /* Skip handshake header */
    
    /* Version */
    version = (record.data[offset] << 8) | record.data[offset + 1];
    offset += 2;
    (void)version;
    
    /* Client Random (32 bytes) */
    memcpy(ctx->client_random, record.data + offset, 32);
    offset += 32;
    
    /* Session ID length */
    session_id_len = record.data[offset++];
    offset += session_id_len;  /* Skip session ID */
    
    if(tls12_is_dtls(ctx)) {
        uint8_t cookie_len;
        if(offset >= record.length) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        cookie_len = record.data[offset++];
        if(offset + cookie_len > record.length) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        if(cookie_len == 0 ||
           dtls_verify_cookie(&ctx->base, record.data + offset, cookie_len) != NOXTLS_RETURN_SUCCESS) {
            rc = tls12_send_hello_verify_request(ctx, record.data, record.length);
            if(record.data) free(record.data);
            return (rc == NOXTLS_RETURN_SUCCESS) ? NOXTLS_RETURN_TIMEOUT : rc;
        }
        offset += cookie_len;
    }
    
    /* Cipher suites length */
    cipher_suites_len = (record.data[offset] << 8) | record.data[offset + 1];
    offset += 2;
    
    /* Parse and select cipher suite from client's list */
    uint16_t selected_suite = 0;
    uint16_t supported_suites_10_11[] = {
        TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA,
        TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA,
        TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA
    };
    uint16_t supported_suites_12[] = {
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_CBC_SHA256,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_CBC_SHA384,
        TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA
    };
    uint16_t *supported_suites = (ctx->base.base.version <= TLS_VERSION_1_1) ? supported_suites_10_11 : supported_suites_12;
    uint32_t num_supported = (ctx->base.base.version <= TLS_VERSION_1_1)
        ? (sizeof(supported_suites_10_11) / sizeof(supported_suites_10_11[0]))
        : (sizeof(supported_suites_12) / sizeof(supported_suites_12[0]));
    uint32_t cipher_suites_count = (uint32_t)cipher_suites_len >> 1;
    
    for(uint32_t i = 0; i < cipher_suites_count && i < num_supported; i++) {
        uint16_t client_suite = (record.data[offset + i*2] << 8) | record.data[offset + i*2 + 1];
        for(uint32_t j = 0; j < num_supported; j++) {
            if(client_suite == supported_suites[j]) {
                selected_suite = client_suite;
                break;
            }
        }
        if(selected_suite != 0) {
            break;
        }
    }
    
    if(selected_suite == 0) {
        noxtls_debug_printf("ERROR: No supported cipher suite found in client's list\n");
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    ctx->cipher_suite = selected_suite;
    noxtls_debug_printf("Selected cipher suite: 0x%04X\n", ctx->cipher_suite);
    fflush(stdout);
    offset += cipher_suites_len;
    
    /* Compression methods length */
    compression_methods_len = record.data[offset++];
    offset += compression_methods_len;
    
    /* Parse extensions if present */
    if(offset < record.length) {
        uint32_t extensions_len = record.length - offset;
        if(extensions_len >= 2) {
            noxtls_tls_parse_extensions(record.data + offset, extensions_len, &ctx->client_extensions);
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
noxtls_return_t tls12_send_server_hello(tls12_context_t *ctx)
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
    
    /* Build Server Hello message */
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
    server_hello[offset++] = 0x00;  /* No session ID */
    
    /* Cipher suite (2 bytes) */
    server_hello[offset++] = (ctx->cipher_suite >> 8) & 0xFF;
    server_hello[offset++] = ctx->cipher_suite & 0xFF;
    
    /* Compression method (1 byte) */
    server_hello[offset++] = 0x00;  /* NULL compression */
    /* Extensions: TLS 1.2 may send renegotiation_info and/or RFC 7250 server_certificate_type (RPK) */
    if(ctx->base.base.version >= TLS_VERSION_1_2) {
        uint16_t ext_block_len = 0;
        int have_reneg = (ctx->renegotiation_in_progress && ctx->previous_verify_data_len > 0);
        int have_rpk = 0;
        int have_mfl = (ctx->max_fragment_length_code >= 1 && ctx->max_fragment_length_code <= 4);
        if(ctx->server_use_rpk) {
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
            uint16_t elen = (uint16_t)(1 + ctx->previous_verify_data_len);
            ext_block_len += 4 + elen;
        }
        if(have_rpk) {
            ext_block_len += 4 + 1;  /* type(2)+len(2)+cert_type(1) */
        }
        if(have_mfl) {
            ext_block_len += 4 + 1;  /* RFC 6066: max_fragment_length type(2)+len(2)+code(1) */
        }
        if(ext_block_len > 0 && offset + 2 + ext_block_len <= TLS_SERVER_HELLO_DEFAULT_SIZE) {
            server_hello[offset++] = (uint8_t)(ext_block_len >> 8);
            server_hello[offset++] = (uint8_t)(ext_block_len & 0xFF);
            if(have_reneg) {
                uint16_t elen = (uint16_t)(1 + ctx->previous_verify_data_len);
                server_hello[offset++] = (uint8_t)(TLS_EXTENSION_RENEGOTIATION_INFO >> 8);
                server_hello[offset++] = (uint8_t)(TLS_EXTENSION_RENEGOTIATION_INFO & 0xFF);
                server_hello[offset++] = (uint8_t)(elen >> 8);
                server_hello[offset++] = (uint8_t)(elen & 0xFF);
                server_hello[offset++] = ctx->previous_verify_data_len;
                memcpy(server_hello + offset, ctx->previous_server_verify_data, ctx->previous_verify_data_len);
                offset += ctx->previous_verify_data_len;
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
        } else {
            server_hello[offset++] = 0x00;
            server_hello[offset++] = 0x00;
        }
    } else {
        server_hello[offset++] = 0x00;
        server_hello[offset++] = 0x00;
    }
    /* Update handshake message length */
    uint32_t handshake_len = offset - 4;
    server_hello[1] = (handshake_len >> 16) & 0xFF;
    server_hello[2] = (handshake_len >> 8) & 0xFF;
    server_hello[3] = handshake_len & 0xFF;
    
    /* Append to handshake messages (for Finished verify_data computation) */
    tls12_append_handshake_message(ctx, server_hello, offset);
    
    /* Send via record layer */
    rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, server_hello, offset);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        tls12_inc_send_seq(ctx);
    }
    if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return rc;
}

/**
 * @brief TLS 1.2 Server: Send Certificate
 */
noxtls_return_t tls12_send_certificate(tls12_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    if(ctx->server_cert == NULL || ctx->server_cert_len == 0) {
        return NOXTLS_RETURN_FAILED;
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
    
    /* Build Certificate message */
    certificate[offset++] = TLS_HANDSHAKE_CERTIFICATE;
    certificate[offset++] = 0x00;  /* Length (3 bytes) - placeholder */
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;
    
    /* Certificate list length (3 bytes) */
    uint32_t cert_list_len = ctx->server_cert_len + 3;  /* +3 for certificate length field */
    certificate[offset++] = (cert_list_len >> 16) & 0xFF;
    certificate[offset++] = (cert_list_len >> 8) & 0xFF;
    certificate[offset++] = cert_list_len & 0xFF;
    
    /* Certificate length (3 bytes) */
    certificate[offset++] = (ctx->server_cert_len >> 16) & 0xFF;
    certificate[offset++] = (ctx->server_cert_len >> 8) & 0xFF;
    certificate[offset++] = ctx->server_cert_len & 0xFF;
    
    /* Certificate data */
    if(offset + ctx->server_cert_len > TLS_HANDSHAKE_WORKSPACE_SIZE) {
        if(certificate != ctx->handshake_workspace) NOXTLS_SECURE_FREE(certificate, TLS_HANDSHAKE_WORKSPACE_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(certificate + offset, ctx->server_cert, ctx->server_cert_len);
    offset += ctx->server_cert_len;
    
    /* Update handshake message length */
    uint32_t handshake_len = offset - 4;
    certificate[1] = (handshake_len >> 16) & 0xFF;
    certificate[2] = (handshake_len >> 8) & 0xFF;
    certificate[3] = handshake_len & 0xFF;
    
    /* Append to handshake messages (for Finished verify_data computation) */
    tls12_append_handshake_message(ctx, certificate, offset);
    
    /* Send via record layer */
    rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, certificate, offset);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        tls12_inc_send_seq(ctx);
    }
    if(certificate != ctx->handshake_workspace) NOXTLS_SECURE_FREE(certificate, TLS_HANDSHAKE_WORKSPACE_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return rc;
}

/**
 * @brief TLS 1.2 Server: Send Server Key Exchange
 */
noxtls_return_t tls12_send_server_key_exchange(tls12_context_t *ctx)
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
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384);
    int is_dhe_kex = (ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_CBC_SHA384);
    
    if(is_rsa_kex) {
        /* RSA key exchange: Server Key Exchange is not sent */
        return NOXTLS_RETURN_SUCCESS;
    } else if(is_dhe_kex) {
        uint16_t named_group;
        uint8_t *skx_buf = (ctx->handshake_workspace != NULL) ? ctx->handshake_workspace : (uint8_t*)noxtls_malloc(2048);
        uint32_t skx_len = 0;
        noxtls_return_t rc;
        if(skx_buf == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        if(tls12_cipher_suite_to_ffdhe_group(ctx->cipher_suite, &named_group) != NOXTLS_RETURN_SUCCESS) {
            if(skx_buf != ctx->handshake_workspace) noxtls_free(skx_buf);
            return NOXTLS_RETURN_FAILED;
        }
        tls_dhe_context_t *dhe_ctx = (tls_dhe_context_t*)malloc(sizeof(tls_dhe_context_t));
        if(dhe_ctx == NULL) {
            if(skx_buf != ctx->handshake_workspace) noxtls_free(skx_buf);
            return NOXTLS_RETURN_FAILED;
        }
        rc = tls_dhe_context_init(dhe_ctx, named_group);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(dhe_ctx);
            if(skx_buf != ctx->handshake_workspace) noxtls_free(skx_buf);
            return rc;
        }
        ctx->dhe_ctx = dhe_ctx;
        rc = tls12_dhe_send_server_key_exchange(ctx, dhe_ctx, skx_buf, 2048, &skx_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            tls_dhe_context_free(dhe_ctx);
            free(dhe_ctx);
            ctx->dhe_ctx = NULL;
            if(skx_buf != ctx->handshake_workspace) noxtls_free(skx_buf);
            return rc;
        }
        tls12_append_handshake_message(ctx, skx_buf, skx_len);
        tls12_inc_send_seq(ctx);
        if(skx_buf != ctx->handshake_workspace) noxtls_free(skx_buf);
        return rc;
    } else {
        noxtls_return_t rc;
        /* ECDHE: Send server's ephemeral public key */
        tls_ecdhe_context_t *ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
        
        if(ecdhe_ctx == NULL) {
            /* Initialize ECDHE context if not already done */
            uint16_t named_group;
            if(tls12_cipher_suite_to_named_curve(ctx->cipher_suite, &named_group) != NOXTLS_RETURN_SUCCESS) {
                noxtls_debug_printf("ERROR: Failed to determine named curve for cipher suite 0x%04X\n", ctx->cipher_suite);
                fflush(stdout);
                return NOXTLS_RETURN_FAILED;
            }
            
            noxtls_debug_printf("Initializing ECDHE context with named group: %d\n", named_group);
            fflush(stdout);
            
            ecdhe_ctx = (tls_ecdhe_context_t*)malloc(sizeof(tls_ecdhe_context_t));
            if(ecdhe_ctx == NULL) {
                return NOXTLS_RETURN_FAILED;
            }
            
            rc = tls_ecdhe_context_init(ecdhe_ctx, named_group);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_debug_printf("ERROR: Failed to initialize ECDHE context: %d\n", rc);
                fflush(stdout);
                free(ecdhe_ctx);
                return rc;
            }
            
            noxtls_debug_printf("Generating server ephemeral key pair (this may take a moment)...\n");
            fflush(stdout);
            
            /* Generate ephemeral key pair */
            rc = tls_ecdhe_generate_ephemeral_key(ecdhe_ctx);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_debug_printf("ERROR: Failed to generate ephemeral key: %d\n", rc);
                fflush(stdout);
                tls_ecdhe_context_free(ecdhe_ctx);
                free(ecdhe_ctx);
                return rc;
            }
            
            noxtls_debug_printf("Server ephemeral key generated successfully\n");
            fflush(stdout);
            
            ctx->ecdhe_ctx = ecdhe_ctx;
        }
        
        /* Build Server Key Exchange message ourselves to have control over handshake message accumulation */
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
        
        /* Build Server Key Exchange message */
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
        rc = tls_ecdhe_get_public_key_encoded(ecdhe_ctx, public_key_encoded, &public_key_len);
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

        if(ctx->crypto_provider && ctx->crypto_provider->ops && ctx->crypto_provider->ops->rsa_sign && ctx->server_private_key_handle) {
            uint32_t to_sign_len = TLS_RANDOM_SIZE + TLS_RANDOM_SIZE + params_len;
            if(to_sign_len <= 320) {
                memcpy(to_sign, ctx->client_random, TLS_RANDOM_SIZE);
                memcpy(to_sign + TLS_RANDOM_SIZE, ctx->server_random, TLS_RANDOM_SIZE);
                memcpy(to_sign + TLS_RANDOM_SIZE * 2, server_key_exchange + params_start, params_len);
                uint32_t sig_len = 512;
                rc = ctx->crypto_provider->ops->rsa_sign(ctx->crypto_provider->ctx, ctx->server_private_key_handle,
                        to_sign, to_sign_len, sig_buf, &sig_len, (noxtls_crypto_hash_algo_t)NOXTLS_HASH_SHA_256);
                if(rc == NOXTLS_RETURN_SUCCESS && offset + 4 + sig_len <= 1024) {
                    server_key_exchange[offset++] = 0x04;
                    server_key_exchange[offset++] = 0x01;
                    server_key_exchange[offset++] = (sig_len >> 8) & 0xFF;
                    server_key_exchange[offset++] = sig_len & 0xFF;
                    memcpy(server_key_exchange + offset, sig_buf, sig_len);
                    offset += sig_len;
                }
            }
        } else if(ctx->server_private_rsa != NULL) {
            uint32_t to_sign_len = TLS_RANDOM_SIZE + TLS_RANDOM_SIZE + params_len;
            if(to_sign_len <= 320) {
                memcpy(to_sign, ctx->client_random, TLS_RANDOM_SIZE);
                memcpy(to_sign + TLS_RANDOM_SIZE, ctx->server_random, TLS_RANDOM_SIZE);
                memcpy(to_sign + TLS_RANDOM_SIZE * 2, server_key_exchange + params_start, params_len);
                uint32_t sig_len = 512;
                rc = noxtls_rsa_sign((const rsa_key_t *)ctx->server_private_rsa, to_sign, to_sign_len,
                                     sig_buf, &sig_len, NOXTLS_HASH_SHA_256);
                if(rc == NOXTLS_RETURN_SUCCESS && offset + 4 + sig_len <= 1024) {
                    server_key_exchange[offset++] = 0x04;
                    server_key_exchange[offset++] = 0x01;
                    server_key_exchange[offset++] = (sig_len >> 8) & 0xFF;
                    server_key_exchange[offset++] = sig_len & 0xFF;
                    memcpy(server_key_exchange + offset, sig_buf, sig_len);
                    offset += sig_len;
                }
            }
        }
        if((ctx->server_private_rsa == NULL && !(ctx->crypto_provider && ctx->crypto_provider->ops && ctx->crypto_provider->ops->rsa_sign && ctx->server_private_key_handle)) || offset <= (params_start + params_len)) {
            server_key_exchange[offset++] = 0x00;
            server_key_exchange[offset++] = 0x00;
            server_key_exchange[offset++] = 0x00;
            server_key_exchange[offset++] = 0x00;
        }
        uint32_t handshake_len = offset - 4;
        server_key_exchange[1] = (handshake_len >> 16) & 0xFF;
        server_key_exchange[2] = (handshake_len >> 8) & 0xFF;
        server_key_exchange[3] = handshake_len & 0xFF;
        noxtls_debug_printf("Sending Server Key Exchange (ECDHE), message length: %u bytes\n", offset);
        fflush(stdout);
        
        /* Append to handshake messages (for Finished verify_data computation) */
        tls12_append_handshake_message(ctx, server_key_exchange, offset);
        
        /* Send via record layer */
        rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, server_key_exchange, offset);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_debug_printf("Server Key Exchange sent successfully\n");
            fflush(stdout);
            tls12_inc_send_seq(ctx);
        } else {
            noxtls_debug_printf("ERROR: Failed to send Server Key Exchange: %d\n", rc);
            fflush(stdout);
        }
        if(server_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_key_exchange, TLS_SERVER_KEY_EXCHANGE_WORKSPACE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return rc;
    }
}

/**
 * @brief TLS 1.2 Server: Send Server Hello Done
 */
noxtls_return_t tls12_send_server_hello_done(tls12_context_t *ctx)
{
    uint8_t server_hello_done[4];
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Build Server Hello Done message */
    server_hello_done[0] = TLS_HANDSHAKE_SERVER_HELLO_DONE;
    server_hello_done[1] = 0x00;
    server_hello_done[2] = 0x00;
    server_hello_done[3] = 0x00;  /* Length is 0 */
    
    /* Append to handshake messages (for Finished verify_data computation) */
    tls12_append_handshake_message(ctx, server_hello_done, 4);
    
    /* Send via record layer */
    rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, server_hello_done, 4);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        tls12_inc_send_seq(ctx);
    }
    return rc;
}

/**
 * @brief TLS 1.2 Server: Receive Client Key Exchange
 */
noxtls_return_t tls12_recv_client_key_exchange(tls12_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    
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
    
    if(record.type != TLS_RECORD_HANDSHAKE) {
        if(record.data) noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    if(record.data[0] != TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE) {
        if(record.data) noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    tls12_inc_recv_seq(ctx);
    
    /* Parse Client Key Exchange message */
    uint32_t msg_offset = 4;  /* Skip handshake header */
    
    /* Determine key exchange method based on cipher suite */
    int is_rsa_kex = (ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_ARIA_128_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384);
    
    if(is_rsa_kex) {
        /* RSA Key Exchange: Extract encrypted premaster secret */
        if(msg_offset + 2 > record.length) {
            if(record.data) noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        
        uint16_t encrypted_premaster_len = (record.data[msg_offset] << 8) | record.data[msg_offset + 1];
        msg_offset += 2;
        
        if(msg_offset + encrypted_premaster_len > record.length || encrypted_premaster_len > TLS_CLIENT_KEY_EXCHANGE_MAX_LEN) {
            if(record.data) noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        
        if(ctx->server_private_rsa == NULL &&
           !(ctx->crypto_provider && ctx->crypto_provider->ops && ctx->crypto_provider->ops->rsa_decrypt && ctx->server_private_key_handle)) {
            noxtls_debug_printf("ERROR: RSA key exchange requires server private key\n");
            if(record.data) noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        ctx->premaster_secret_len = sizeof(ctx->premaster_secret);
        if(ctx->crypto_provider && ctx->crypto_provider->ops && ctx->crypto_provider->ops->rsa_decrypt && ctx->server_private_key_handle) {
            rc = ctx->crypto_provider->ops->rsa_decrypt(ctx->crypto_provider->ctx, ctx->server_private_key_handle,
                    record.data + msg_offset, encrypted_premaster_len, ctx->premaster_secret, &ctx->premaster_secret_len);
        } else {
            rc = noxtls_rsa_decrypt((const rsa_key_t *)ctx->server_private_rsa,
                                    record.data + msg_offset, encrypted_premaster_len,
                                    ctx->premaster_secret, &ctx->premaster_secret_len);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(record.data) noxtls_free(record.data);
            noxtls_debug_printf("ERROR: RSA decrypt premaster failed: %d\n", rc);
            return rc;
        }
        if(ctx->premaster_secret_len != 48) {
            if(record.data) noxtls_free(record.data);
            noxtls_debug_printf("ERROR: Invalid premaster secret length %u\n", ctx->premaster_secret_len);
            return NOXTLS_RETURN_FAILED;
        }
    } else if(ctx->dhe_ctx != NULL) {
        /* DHE: Parse client's ephemeral public key and compute shared secret */
        tls_dhe_context_t *dhe_ctx = (tls_dhe_context_t*)ctx->dhe_ctx;
        rc = tls12_dhe_recv_client_key_exchange(ctx, dhe_ctx, record.data, record.length);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(record.data) noxtls_free(record.data);
            return rc;
        }
        tls12_append_handshake_message(ctx, record.data, record.length);
        if(record.data) noxtls_free(record.data);
        return NOXTLS_RETURN_SUCCESS;
    } else {
        /* ECDHE: Extract client's ephemeral public key and compute shared secret */
        tls_ecdhe_context_t *ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
        
        if(ecdhe_ctx == NULL) {
            if(record.data) noxtls_free(record.data);
            noxtls_debug_printf("ERROR: ECDHE context not initialized\n");
            return NOXTLS_RETURN_FAILED;
        }
        
        /* Parse Client Key Exchange message (record already received) */
        uint32_t ecdhe_msg_offset = 4;  /* Skip handshake header */
        uint8_t public_key_len;
        ecc_point_t peer_public_key;
        
        /* Public key length */
        if(ecdhe_msg_offset >= record.length) {
            if(record.data) noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        public_key_len = record.data[ecdhe_msg_offset++];
        
        /* Public key */
        if(ecdhe_msg_offset + public_key_len > record.length) {
            if(record.data) noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        
        /* Decode peer's public key */
        rc = tls_decode_ecc_point_uncompressed(record.data + ecdhe_msg_offset, public_key_len, &peer_public_key, ecdhe_ctx->curve_type);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(record.data) noxtls_free(record.data);
            return rc;
        }
        
        /* Compute shared secret */
        rc = tls_ecdhe_compute_shared_secret(ecdhe_ctx, &peer_public_key);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(record.data) noxtls_free(record.data);
            return rc;
        }
        
        /* Create premaster secret from shared secret for TLS 1.2 */
        if(ecdhe_ctx->shared_secret != NULL && ecdhe_ctx->shared_secret_len > 0) {
            uint32_t premaster_len = tls12_get_ecdh_premaster_len(ecdhe_ctx->named_group);
            if(premaster_len == 0 || ecdhe_ctx->shared_secret_len < premaster_len ||
               premaster_len > sizeof(ctx->premaster_secret)) {
                if(record.data) noxtls_free(record.data);
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
            return NOXTLS_RETURN_FAILED;
        }
    }
    
    /* Append to handshake messages (for Finished verify_data computation) */
    tls12_append_handshake_message(ctx, record.data, record.length);
    
    if(record.data) noxtls_free(record.data);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Server: Receive Change Cipher Spec from Client
 */
noxtls_return_t tls12_recv_change_cipher_spec_client(tls12_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    
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
    
    if(record.type != TLS_RECORD_CHANGE_CIPHER_SPEC || record.length != 1) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    if(record.data[0] != TLS_RECORD_CCS_PAYLOAD) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    tls12_inc_recv_seq(ctx);
    if(ctx->base.base.role == TLS_ROLE_SERVER) {
        ctx->client_seq_num = 0;
    } else {
        ctx->server_seq_num = 0;
    }
    tls12_dtls_on_recv_ccs(ctx);
    
    if(record.data) free(record.data);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Server: Receive Finished from Client
 */
noxtls_return_t tls12_recv_finished_client(tls12_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    
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
    }

    noxtls_debug_printf("[TLS12_DEBUG] recv_finished_client: post-decrypt header type=%u len=%u\n",
                          finished_len > 0 ? finished_msg[0] : 0, finished_len);
    fflush(stdout);
    if(finished_len != 16 || finished_msg[0] != TLS_HANDSHAKE_FINISHED) {
        noxtls_debug_printf("[TLS12_DEBUG] recv_finished_client: bad decrypted header type=%u len=%u\n",
                              finished_msg[0], finished_len);
        fflush(stdout);
        if(decrypted != ctx->record_workspace) noxtls_free(decrypted);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Verify finished message */
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
    
    /* Save client verify_data for RFC 5746 renegotiation_info */
    memcpy(ctx->previous_client_verify_data, finished_msg + 4, 12);
    /* Compare verify_data (starts at offset 4 in Finished message) */
    if(memcmp(finished_msg + 4, computed_verify_data, 12) != 0) {
        noxtls_debug_printf("ERROR: Client Finished message verification failed!\n");
        noxtls_debug_printf("  received: ");
        for(uint32_t i = 0; i < 12; i++) noxtls_debug_printf("%02X ", finished_msg[4 + i]);
        noxtls_debug_printf("\n  expected: ");
        for(uint32_t i = 0; i < 12; i++) noxtls_debug_printf("%02X ", computed_verify_data[i]);
        noxtls_debug_printf("\n");
        fflush(stdout);
        if(decrypted != ctx->record_workspace) noxtls_free(decrypted);
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_debug_printf("[TLS12_DEBUG] recv_finished_client: verify_data match\n");
    fflush(stdout);

    if(record.data) free(record.data);
    if(decrypted != ctx->record_workspace) noxtls_free(decrypted);
    /* Finished is always a record that consumes a sequence number */
    tls12_inc_recv_seq(ctx);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Server: Send Change Cipher Spec
 */
noxtls_return_t tls12_send_change_cipher_spec_server(tls12_context_t *ctx)
{
    uint8_t change_cipher_spec = 0x01;
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_CHANGE_CIPHER_SPEC, &change_cipher_spec, 1);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        tls12_inc_send_seq(ctx);
        /* Reset sequence number for new cipher state (server write state) */
        ctx->server_seq_num = 0;
        tls12_dtls_on_send_ccs(ctx);
    }
    return rc;
}

/**
 * @brief TLS 1.2 Server: Send Finished
 */
noxtls_return_t tls12_send_finished_server(tls12_context_t *ctx)
{
    uint8_t finished[TLS_MAX_SECRET_LEN];
    uint32_t offset = 0;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Build Finished message */
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
    
    /* Append Finished message to handshake messages (but not the Finished message itself) */
    /* Note: Finished message is NOT included in the handshake hash */
    
    /* After Change Cipher Spec, Finished message must be encrypted */
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
        }
        return rc;
    }
    
    /* Encrypt the Finished message before sending */
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
        noxtls_debug_printf("ERROR: Failed to encrypt Finished message: %d\n", rc);
        fflush(stdout);
        if(encrypted_finished != ctx->record_workspace) noxtls_free(encrypted_finished);
        return rc;
    }
    rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, encrypted_finished, encrypted_len);
    if(encrypted_finished != ctx->record_workspace) noxtls_free(encrypted_finished);
    return rc;
}

/**
 * @brief TLS 1.2 Server: Accept connection
 */
noxtls_return_t tls12_accept(tls12_context_t *ctx)
{
    noxtls_return_t rc;
    
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
        rc = tls12_recv_client_hello(ctx);
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
    
    /* Send Server Hello */
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_SEND_SH);
    rc = tls12_send_server_hello(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_SH, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_SH, rc);
    
    /* Send Certificate */
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_SEND_CERT);
    rc = tls12_send_certificate(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_CERT, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_CERT, rc);
    
    /* Send Server Key Exchange (if needed for selected cipher suite) */
    rc = tls12_send_server_key_exchange(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    /* Send Server Hello Done */
    rc = tls12_send_server_hello_done(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    /* Receive Client Key Exchange */
    rc = tls12_recv_client_key_exchange(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
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
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 2u, ctx->cipher_suite);
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_KEY_SCHEDULE, rc);
    
    /* Receive Change Cipher Spec */
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED);
    rc = tls12_recv_change_cipher_spec_client(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED, rc);
        return rc;
    }
    
    /* Receive Finished */
    rc = tls12_recv_finished_client(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED, rc);
    
    /* Send Change Cipher Spec */
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED);
    rc = tls12_send_change_cipher_spec_server(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED, rc);
        return rc;
    }
    
    /* Send Finished */
    rc = tls12_send_finished_server(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED, rc);
    
    ctx->base.base.state = TLS_STATE_CONNECTED;
    dtls_mark_validated(&ctx->base);
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_CONNECTED);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2: Send application data
 */
noxtls_return_t tls12_send(tls12_context_t *ctx, const uint8_t *data, uint32_t len)
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
    }
    if(encrypted_record != ctx->record_workspace) noxtls_free(encrypted_record);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2: Receive application data
 */
noxtls_return_t tls12_recv(tls12_context_t *ctx, uint8_t *data, uint32_t *len)
{
    tls_record_t record;

    if(ctx == NULL || data == NULL || len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(ctx->base.base.state != TLS_STATE_CONNECTED) {
        return NOXTLS_RETURN_FAILED;
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
                noxtls_debug_printf("[TLS12_DEBUG] tls12_recv: alert decrypt failed rc=%d\n", rc);
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
                noxtls_debug_printf("[TLS12_DEBUG] tls12_recv: alert level=%u (%s) desc=%u (%s)\n",
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
                rc = tls12_send_client_hello(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = tls12_recv_server_hello(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = tls12_recv_certificate(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = tls12_recv_server_key_exchange(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = tls12_recv_server_hello_done(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = tls12_send_client_key_exchange(ctx);
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
                rc = tls12_send_change_cipher_spec(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = tls12_send_finished(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = tls12_recv_change_cipher_spec(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = tls12_recv_finished(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                ctx->base.base.state = TLS_STATE_CONNECTED;
                ctx->renegotiation_in_progress = 0;
                (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
                continue; /* Read next record (application data or another HelloRequest) */
            }
            /* Server: ClientHello while connected triggers renegotiation */
            if(ctx->base.base.role == TLS_ROLE_SERVER && handshake_len >= 1 &&
               handshake_buf[0] == TLS_HANDSHAKE_CLIENT_HELLO) {
                if(ctx->handshake_messages) {
                    free(ctx->handshake_messages);
                    ctx->handshake_messages = NULL;
                    ctx->handshake_messages_len = 0;
                }
                ctx->renegotiation_in_progress = 1;
                ctx->base.base.state = TLS_STATE_HANDSHAKING;
                rc = tls12_parse_client_hello_from_buf(ctx, handshake_buf, handshake_len);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
                    ctx->renegotiation_in_progress = 0;
                    return rc;
                }
                rc = tls12_send_server_hello(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = tls12_send_certificate(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = tls12_send_server_key_exchange(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = tls12_send_server_hello_done(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = tls12_recv_client_key_exchange(ctx);
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
                rc = tls12_recv_change_cipher_spec_client(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = tls12_recv_finished_client(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = tls12_send_change_cipher_spec_server(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = tls12_send_finished_server(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                ctx->base.base.state = TLS_STATE_CONNECTED;
                ctx->renegotiation_in_progress = 0;
                (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
                continue;
            }
            /* Ignore other post-handshake messages (e.g., NewSessionTicket) and read next record. */
            (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
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
            noxtls_debug_printf("[TLS12_DEBUG] tls12_recv: app decrypt failed rc=%d\n", rc);
            fflush(stdout);
        } else {
            noxtls_debug_printf("[TLS12_DEBUG] tls12_recv: app decrypt ok len=%u\n", *len);
            fflush(stdout);
        }
        return rc;
    }
}

/**
 * @brief TLS 1.2: Close connection
 */
noxtls_return_t tls12_close(tls12_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Send close_notify alert */
    noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_WARNING, TLS_ALERT_CLOSE_NOTIFY);
    
    ctx->base.base.state = TLS_STATE_CLOSED;
    
    return NOXTLS_RETURN_SUCCESS;
}

