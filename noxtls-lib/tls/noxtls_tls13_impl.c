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
* File:    noxtls_tls13_impl.c
* Summary: TLS 1.3 Implementation (alternate)
*
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common/NOXTLS_memory.h"
#include "common/NOXTLS_memory_compat.h"
#include "common/noxtls_ct.h"
#include "NOXTLS_tls13.h"
#include "drbg/NOXTLS_drbg.h"
#include "certs/noxtls_x509.h"
#include "NOXTLS_tls_kdf.h"
#include "NOXTLS_tls_key_exchange.h"
#include "pkc/rsa/noxtls_rsa.h"
#include "mdigest/NOXTLS_hash.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "noxtls_tls_noxsight.h"

static char tls13_keylog_path[512] = {0};

/**
 * @brief Return whether the context is negotiating DTLS 1.3.
 * @param[in] ctx TLS 1.3 context (may be NULL).
 * @return 1 if @p ctx uses `DTLS_VERSION_1_3`; 0 otherwise.
 */
static int tls13_is_dtls(const tls13_context_t *ctx)
{
    return (ctx != NULL && ctx->base.base.version == DTLS_VERSION_1_3);
}

/**
 * @brief HKDF-Expand-Label dispatch for TLS 1.3 or DTLS 1.3 (RFC 8446 / RFC 9147).
 * @param[in] ctx          Context used to select TLS vs DTLS KDF helpers.
 * @param[in] hash_algo    Hash algorithm for the cipher suite.
 * @param[in] secret       HKDF secret input.
 * @param[in] secret_len   Length of @p secret.
 * @param[in] label        ASCII label bytes (without "tls13 " prefix).
 * @param[in] label_len    Length of @p label.
 * @param[in] context      Optional context bytes for the label.
 * @param[in] context_len  Length of @p context.
 * @param[out] output      Expanded key material.
 * @param[in] output_len   Number of bytes to expand into @p output.
 * @return Result from `tls13_hkdf_expand_label` or `dtls13_hkdf_expand_label`.
 */
static noxtls_return_t tls13_ctx_hkdf_expand_label(const tls13_context_t *ctx,
                                          noxtls_hash_algos_t hash_algo,
                                          const uint8_t *secret, uint32_t secret_len,
                                          const uint8_t *label, uint32_t label_len,
                                          const uint8_t *context, uint32_t context_len,
                                          uint8_t *output, uint32_t output_len)
{
    if(tls13_is_dtls(ctx)) {
        return dtls13_hkdf_expand_label(hash_algo, secret, secret_len, label, label_len, context, context_len, output, output_len);
    }
    return tls13_hkdf_expand_label(hash_algo, secret, secret_len, label, label_len, context, context_len, output, output_len);
}

/**
 * @brief Derive-Secret dispatch for TLS 1.3 or DTLS 1.3.
 * @param[in] ctx           Context used to select TLS vs DTLS KDF helpers.
 * @param[in] hash_algo     Hash algorithm for the cipher suite.
 * @param[in] secret        Input secret (e.g. handshake or master secret).
 * @param[in] secret_len    Length of @p secret.
 * @param[in] label         Derive-Secret label (e.g. "c hs traffic").
 * @param[in] label_len     Length of @p label.
 * @param[in] messages      Handshake transcript hashed as context (may be NULL if length 0).
 * @param[in] messages_len  Length of @p messages.
 * @param[out] output       Derived secret output buffer.
 * @param[in] output_len    Length to derive.
 * @return Result from `tls13_derive_secret` or `dtls13_derive_secret`.
 */
static noxtls_return_t tls13_ctx_derive_secret(const tls13_context_t *ctx,
                                      noxtls_hash_algos_t hash_algo,
                                      const uint8_t *secret, uint32_t secret_len,
                                      const uint8_t *label, uint32_t label_len,
                                      const uint8_t *messages, uint32_t messages_len,
                                      uint8_t *output, uint32_t output_len)
{
    if(tls13_is_dtls(ctx)) {
        return dtls13_derive_secret(hash_algo, secret, secret_len, label, label_len, messages, messages_len, output, output_len);
    }
    return tls13_derive_secret(hash_algo, secret, secret_len, label, label_len, messages, messages_len, output, output_len);
}

/**
 * @brief Set the NSS key log file path for Wireshark decryption (SSLKEYLOGFILE format).
 *
 * If @p path is NULL or empty, clears the configured path; `SSLKEYLOGFILE` in the
 * environment is still consulted at write time when no path is set.
 *
 * @param[in] path Filesystem path, or NULL to disable the explicit path.
 */
void noxtls_tls13_set_keylog_file(const char *path)
{
    if(path == NULL || *path == '\0') {
        tls13_keylog_path[0] = '\0';
        return;
    }
    strncpy(tls13_keylog_path, path, sizeof(tls13_keylog_path) - 1);
    tls13_keylog_path[sizeof(tls13_keylog_path) - 1] = '\0';
}

/**
 * @brief Append one line to the key log file (label, client_random, secret).
 * @param[in] label         NSS key log label (e.g. CLIENT_HANDSHAKE_TRAFFIC_SECRET).
 * @param[in] client_random 32-byte ClientHello random.
 * @param[in] secret        Secret bytes to log.
 * @param[in] secret_len    Length of @p secret.
 */
static void tls13_keylog_write(const char *label, const uint8_t *client_random,
                               const uint8_t *secret, uint32_t secret_len)
{
    const char *path = tls13_keylog_path[0] ? tls13_keylog_path : getenv("SSLKEYLOGFILE");
    if(path == NULL || client_random == NULL || secret == NULL) {
        return;
    }

    FILE *fp = fopen(path, "a");
    if(fp == NULL) {
        return;
    }

    fprintf(fp, "%s ", label);
    for(uint32_t i = 0; i < 32; i++) {
        fprintf(fp, "%02X", client_random[i]);
    }
    fprintf(fp, " ");
    for(uint32_t i = 0; i < secret_len; i++) {
        fprintf(fp, "%02X", secret[i]);
    }
    fprintf(fp, "\n");
    fclose(fp);
}

/**
 * @brief Append a handshake message to the running transcript hash input buffer.
 * @param[in,out] ctx  Context owning `handshake_messages`.
 * @param[in] data     Handshake message bytes (type + 3-byte length + body).
 * @param[in] len      Length of @p data.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers;
 *         `NOXTLS_RETURN_FAILED` on realloc overflow or failure.
 */
static noxtls_return_t tls13_append_handshake_message(tls13_context_t *ctx, const uint8_t *data, uint32_t len)
{
    if(ctx == NULL || data == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(len >= 4) {
        uint32_t hs_len = ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
        noxtls_debug_printf("[TLS13_DEBUG] append_handshake: type=0x%02X hs_len=%u total_len=%u\n",
                              data[0], hs_len, len);
    } else {
        noxtls_debug_printf("[TLS13_DEBUG] append_handshake: len=%u\n", len);
    }

    if(len > UINT32_MAX - ctx->handshake_messages_len) {
        return NOXTLS_RETURN_FAILED;
    }
    uint32_t new_len = ctx->handshake_messages_len + len;
    uint8_t *new_buffer = (uint8_t*)realloc(ctx->handshake_messages, new_len);
    if(new_buffer == NULL && len > 0) {
        return NOXTLS_RETURN_FAILED;
    }

    ctx->handshake_messages = new_buffer;
    memcpy(ctx->handshake_messages + ctx->handshake_messages_len, data, len);
    ctx->handshake_messages_len = new_len;
    noxtls_debug_printf("[TLS13_DEBUG] handshake_messages_len=%u\n", ctx->handshake_messages_len);
    if(ctx->handshake_messages_len >= 16) {
        uint8_t *buf = ctx->handshake_messages;
        uint32_t total = ctx->handshake_messages_len;
        noxtls_debug_printf("[TLS13_DEBUG] transcript head: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                              buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
        noxtls_debug_printf("[TLS13_DEBUG] transcript tail: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                              buf[total - 8], buf[total - 7], buf[total - 6], buf[total - 5],
                              buf[total - 4], buf[total - 3], buf[total - 2], buf[total - 1]);
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Map a TLS 1.3 cipher suite to hash algorithm and key lengths.
 * @param[in] cipher_suite Negotiated cipher suite identifier.
 * @param[out] hash_algo   SHA-256 or SHA-384 for the suite.
 * @param[out] hash_len    Hash output length (32 or 48).
 * @param[out] key_len     AEAD key length (16 or 32).
 * @return `NOXTLS_RETURN_SUCCESS` for supported suites; `NOXTLS_RETURN_NULL` or
 *         `NOXTLS_RETURN_INVALID_PARAM` on error.
 */
static noxtls_return_t tls13_get_cipher_params(uint16_t cipher_suite,
                                                 noxtls_hash_algos_t *hash_algo,
                                                 uint32_t *hash_len,
                                                 uint32_t *key_len)
{
    if(hash_algo == NULL || hash_len == NULL || key_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    switch(cipher_suite) {
        case TLS_CIPHER_SUITE_AES_128_GCM_SHA256:
            *hash_algo = NOXTLS_HASH_SHA_256;
            *hash_len = 32;
            *key_len = 16;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_CIPHER_SUITE_AES_256_GCM_SHA384:
            *hash_algo = NOXTLS_HASH_SHA_384;
            *hash_len = 48;
            *key_len = 32;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256:
            *hash_algo = NOXTLS_HASH_SHA_256;
            *hash_len = 32;
            *key_len = 32;
            return NOXTLS_RETURN_SUCCESS;
        default:
            return NOXTLS_RETURN_INVALID_PARAM;
    }
}

/**
 * @brief Hash handshake transcript bytes for Finished and Derive-Secret inputs.
 * @param[in] hash_algo     SHA-256 or SHA-384.
 * @param[in] messages      Transcript bytes (may be NULL if @p messages_len is 0).
 * @param[in] messages_len  Length of @p messages.
 * @param[out] hash         Output digest buffer (at least 48 bytes).
 * @param[out] hash_len     On success, 32 or 48.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` or
 *         `NOXTLS_RETURN_INVALID_ALGORITHM` on error.
 */
static noxtls_return_t tls13_hash_messages(noxtls_hash_algos_t hash_algo,
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
            noxtls_sha256_update(&sha_ctx, (uint8_t*)messages, messages_len);
        }
        *hash_len = 32;
        return noxtls_sha256_finish(&sha_ctx, hash);
    }

    if(hash_algo == NOXTLS_HASH_SHA_384) {
        noxtls_sha512_ctx_t sha_ctx;
        noxtls_sha512_init(&sha_ctx, hash_algo);
        if(messages != NULL && messages_len > 0) {
            noxtls_sha512_update(&sha_ctx, (uint8_t*)messages, messages_len);
        }
        *hash_len = 48;
        return noxtls_sha512_finish(&sha_ctx, hash);
    }

    return NOXTLS_RETURN_INVALID_ALGORITHM;
}

/**
 * @brief Derive handshake traffic secrets and install handshake AEAD keys (RFC 8446 §7.1).
 *
 * Computes early_secret, handshake_secret, client/server handshake traffic secrets,
 * expands record keys and IVs, and writes NSS key log lines when configured.
 * For DTLS 1.3 also derives record-number encryption keys ("sn" label).
 *
 * @param[in,out] ctx               TLS 1.3 context; transcript must be current in `handshake_messages`.
 * @param[in] shared_secret         ECDHE (or PSK) shared secret from key exchange.
 * @param[in] shared_secret_len     Length of @p shared_secret.
 * @return `NOXTLS_RETURN_SUCCESS` on success; error code from cipher lookup, HKDF, or expand steps.
 */
static noxtls_return_t tls13_derive_handshake_keys(tls13_context_t *ctx, const uint8_t *shared_secret, uint32_t shared_secret_len)
{
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    uint32_t prk_len;
    uint8_t derived_secret[64];
    const uint8_t zero_ikm[64] = {0};
    noxtls_return_t rc;

    if(ctx == NULL || shared_secret == NULL || shared_secret_len == 0) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 1u, ctx->cipher_suite);
    noxtls_debug_printf("[TLS13_DEBUG] derive_handshake_keys: cipher=0x%04X hash=%u key_len=%u\n",
                          ctx->cipher_suite, (unsigned)hash_algo, key_len);
    {
        uint8_t transcript_hash[64];
        uint32_t transcript_len = sizeof(transcript_hash);
        if(tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                               transcript_hash, &transcript_len) == NOXTLS_RETURN_SUCCESS) {
            noxtls_debug_printf("[TLS13_DEBUG] transcript hash[0..3]=%02X%02X%02X%02X len=%u hs_len=%u\n",
                                  transcript_hash[0], transcript_hash[1], transcript_hash[2], transcript_hash[3],
                                  transcript_len, ctx->handshake_messages_len);
            noxtls_debug_printf("[TLS13_DEBUG] transcript_hash=");
            for(uint32_t i = 0; i < transcript_len; i++) {
                noxtls_debug_printf("%02X", transcript_hash[i]);
            }
            noxtls_debug_printf("\n");
        }
    }

    noxtls_debug_printf("[TLS13_DEBUG] derive_handshake_keys: shared[0..3]=%02X%02X%02X%02X len=%u\n",
                          shared_secret[0], shared_secret[1], shared_secret[2], shared_secret[3], shared_secret_len);
    noxtls_debug_printf("[TLS13_DEBUG] shared_secret=");
    for(uint32_t i = 0; i < shared_secret_len; i++) {
        noxtls_debug_printf("%02X", shared_secret[i]);
    }
    noxtls_debug_printf("\n");

    prk_len = hash_len;
    rc = hkdf_extract(hash_algo, NULL, 0, zero_ikm, hash_len, ctx->early_secret, &prk_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    NOXTLS_NS_EVENT_SENSITIVE(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_TRACE,
                              NOXTLS_EVT_KEY_SCHEDULE_STAGE,
                              ((uint32_t)ctx->early_secret[0] << 24) |
                              ((uint32_t)ctx->early_secret[1] << 16) |
                              ((uint32_t)ctx->early_secret[2] << 8) |
                              (uint32_t)ctx->early_secret[3],
                              11u);
    noxtls_debug_printf("[TLS13_DEBUG] early_secret[0..3]=%02X%02X%02X%02X\n",
                          ctx->early_secret[0], ctx->early_secret[1], ctx->early_secret[2], ctx->early_secret[3]);

    rc = tls13_ctx_derive_secret(ctx, hash_algo, ctx->early_secret, hash_len,
                             (const uint8_t*)"derived", 7, NULL, 0,
                             derived_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    noxtls_debug_printf("[TLS13_DEBUG] derived_secret[0..3]=%02X%02X%02X%02X\n",
                          derived_secret[0], derived_secret[1], derived_secret[2], derived_secret[3]);

    prk_len = hash_len;
    rc = hkdf_extract(hash_algo, derived_secret, hash_len, shared_secret, shared_secret_len,
                      ctx->handshake_secret, &prk_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 2u, hash_len);
    noxtls_debug_printf("[TLS13_DEBUG] handshake_secret[0..3]=%02X%02X%02X%02X\n",
                          ctx->handshake_secret[0], ctx->handshake_secret[1], ctx->handshake_secret[2], ctx->handshake_secret[3]);

    rc = tls13_ctx_derive_secret(ctx, hash_algo, ctx->handshake_secret, hash_len,
                             (const uint8_t*)"c hs traffic", 12,
                             ctx->handshake_messages, ctx->handshake_messages_len,
                             ctx->client_handshake_traffic_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    noxtls_debug_printf("[TLS13_DEBUG] c_hs_secret[0..3]=%02X%02X%02X%02X\n",
                          ctx->client_handshake_traffic_secret[0], ctx->client_handshake_traffic_secret[1],
                          ctx->client_handshake_traffic_secret[2], ctx->client_handshake_traffic_secret[3]);

    rc = tls13_ctx_derive_secret(ctx, hash_algo, ctx->handshake_secret, hash_len,
                             (const uint8_t*)"s hs traffic", 12,
                             ctx->handshake_messages, ctx->handshake_messages_len,
                             ctx->server_handshake_traffic_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 3u, hash_len);
    noxtls_debug_printf("[TLS13_DEBUG] s_hs_secret[0..3]=%02X%02X%02X%02X\n",
                          ctx->server_handshake_traffic_secret[0], ctx->server_handshake_traffic_secret[1],
                          ctx->server_handshake_traffic_secret[2], ctx->server_handshake_traffic_secret[3]);
    noxtls_debug_printf("[TLS13_DEBUG] s_hs_secret=");
    for(uint32_t i = 0; i < hash_len; i++) {
        noxtls_debug_printf("%02X", ctx->server_handshake_traffic_secret[i]);
    }
    noxtls_debug_printf("\n");
    noxtls_debug_printf("[TLS13_KEYLOG] CLIENT_HANDSHAKE_TRAFFIC_SECRET ");
    for(uint32_t i = 0; i < 32; i++) {
        noxtls_debug_printf("%02X", ctx->client_random[i]);
    }
    noxtls_debug_printf(" ");
    for(uint32_t i = 0; i < hash_len; i++) {
        noxtls_debug_printf("%02X", ctx->client_handshake_traffic_secret[i]);
    }
    noxtls_debug_printf("\n");
    noxtls_debug_printf("[TLS13_KEYLOG] SERVER_HANDSHAKE_TRAFFIC_SECRET ");
    for(uint32_t i = 0; i < 32; i++) {
        noxtls_debug_printf("%02X", ctx->client_random[i]);
    }
    noxtls_debug_printf(" ");
    for(uint32_t i = 0; i < hash_len; i++) {
        noxtls_debug_printf("%02X", ctx->server_handshake_traffic_secret[i]);
    }
    noxtls_debug_printf("\n");
    tls13_keylog_write("CLIENT_HANDSHAKE_TRAFFIC_SECRET", ctx->client_random,
                       ctx->client_handshake_traffic_secret, hash_len);
    tls13_keylog_write("SERVER_HANDSHAKE_TRAFFIC_SECRET", ctx->client_random,
                       ctx->server_handshake_traffic_secret, hash_len);

    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->client_handshake_traffic_secret, hash_len,
                                 (const uint8_t*)"key", 3, NULL, 0,
                                 ctx->client_write_key, key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->client_handshake_traffic_secret, hash_len,
                                 (const uint8_t*)"iv", 2, NULL, 0,
                                 ctx->client_write_iv, 12);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->server_handshake_traffic_secret, hash_len,
                                 (const uint8_t*)"key", 3, NULL, 0,
                                 ctx->server_write_key, key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->server_handshake_traffic_secret, hash_len,
                                 (const uint8_t*)"iv", 2, NULL, 0,
                                 ctx->server_write_iv, 12);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* RFC 9147 §4.2.3: record number encryption keys for DTLS 1.3 handshake */
    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->client_handshake_traffic_secret, hash_len,
                                 (const uint8_t*)"sn", 2, NULL, 0,
                                 ctx->client_handshake_sn_key, DTLS13_RECORD_NUMBER_ENC_LEN);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->server_handshake_traffic_secret, hash_len,
                                 (const uint8_t*)"sn", 2, NULL, 0,
                                 ctx->server_handshake_sn_key, DTLS13_RECORD_NUMBER_ENC_LEN);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    ctx->client_seq_num = 0;
    ctx->server_seq_num = 0;

    noxtls_debug_printf("[TLS13_DEBUG] hs keys: ckey[0..3]=%02X%02X%02X%02X civ[0..3]=%02X%02X%02X%02X "
                          "skey[0..3]=%02X%02X%02X%02X siv[0..3]=%02X%02X%02X%02X\n",
                          ctx->client_write_key[0], ctx->client_write_key[1], ctx->client_write_key[2], ctx->client_write_key[3],
                          ctx->client_write_iv[0], ctx->client_write_iv[1], ctx->client_write_iv[2], ctx->client_write_iv[3],
                          ctx->server_write_key[0], ctx->server_write_key[1], ctx->server_write_key[2], ctx->server_write_key[3],
                          ctx->server_write_iv[0], ctx->server_write_iv[1], ctx->server_write_iv[2], ctx->server_write_iv[3]);
    noxtls_debug_printf("[TLS13_DEBUG] hs server_key=");
    for(uint32_t i = 0; i < key_len; i++) {
        noxtls_debug_printf("%02X", ctx->server_write_key[i]);
    }
    noxtls_debug_printf("\n");
    noxtls_debug_printf("[TLS13_DEBUG] hs server_iv=");
    for(uint32_t i = 0; i < 12; i++) {
        noxtls_debug_printf("%02X", ctx->server_write_iv[i]);
    }
    noxtls_debug_printf("\n");

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Derive master_secret and application traffic secrets after server Finished (RFC 8446 §7.1).
 * @param[in,out] ctx Context with `handshake_secret` and full handshake transcript.
 * @return `NOXTLS_RETURN_SUCCESS` on success; error code from HKDF or cipher lookup.
 */
static noxtls_return_t tls13_derive_application_secrets(tls13_context_t *ctx)
{
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    uint32_t prk_len;
    uint8_t derived_secret[64];
    const uint8_t zero_ikm[64] = {0};
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 4u, ctx->cipher_suite);

    rc = tls13_ctx_derive_secret(ctx, hash_algo, ctx->handshake_secret, hash_len,
                             (const uint8_t*)"derived", 7, NULL, 0,
                             derived_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    prk_len = hash_len;
    rc = hkdf_extract(hash_algo, derived_secret, hash_len, zero_ikm, hash_len,
                      ctx->master_secret, &prk_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_ctx_derive_secret(ctx, hash_algo, ctx->master_secret, hash_len,
                             (const uint8_t*)"c ap traffic", 12,
                             ctx->handshake_messages, ctx->handshake_messages_len,
                             ctx->client_application_traffic_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_ctx_derive_secret(ctx, hash_algo, ctx->master_secret, hash_len,
                             (const uint8_t*)"s ap traffic", 12,
                             ctx->handshake_messages, ctx->handshake_messages_len,
                             ctx->server_application_traffic_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Expand application traffic secrets into AEAD keys, IVs, and DTLS SN keys.
 * @param[in,out] ctx Context with `client_application_traffic_secret` and server counterpart set.
 * @return `NOXTLS_RETURN_SUCCESS` on success; error code from HKDF-Expand-Label steps.
 */
static noxtls_return_t tls13_install_application_keys(tls13_context_t *ctx)
{
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 5u, key_len);

    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->client_application_traffic_secret, hash_len,
                                 (const uint8_t*)"key", 3, NULL, 0,
                                 ctx->client_write_key, key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->client_application_traffic_secret, hash_len,
                                 (const uint8_t*)"iv", 2, NULL, 0,
                                 ctx->client_write_iv, 12);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->server_application_traffic_secret, hash_len,
                                 (const uint8_t*)"key", 3, NULL, 0,
                                 ctx->server_write_key, key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->server_application_traffic_secret, hash_len,
                                 (const uint8_t*)"iv", 2, NULL, 0,
                                 ctx->server_write_iv, 12);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* RFC 9147 §4.2.3: record number encryption keys for DTLS 1.3 application data */
    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->client_application_traffic_secret, hash_len,
                                 (const uint8_t*)"sn", 2, NULL, 0,
                                 ctx->client_sn_key, DTLS13_RECORD_NUMBER_ENC_LEN);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->server_application_traffic_secret, hash_len,
                                 (const uint8_t*)"sn", 2, NULL, 0,
                                 ctx->server_sn_key, DTLS13_RECORD_NUMBER_ENC_LEN);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    ctx->client_seq_num = 0;
    ctx->server_seq_num = 0;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Build TLS 1.3 inner plaintext (content || content_type) for AEAD (RFC 8446 §5.2).
 * @param[in] content       Handshake or application bytes (may be NULL if @p content_len is 0).
 * @param[in] content_len   Length of @p content.
 * @param[in] content_type  Real record type stored in the final byte.
 * @param[out] output       Buffer for inner plaintext.
 * @param[in,out] output_len On input, size of @p output; on success, bytes written; if too small, required size.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` or `NOXTLS_RETURN_FAILED` on error.
 */
static noxtls_return_t tls13_build_inner_plaintext(const uint8_t *content, uint32_t content_len,
                                                     uint8_t content_type,
                                                     uint8_t *output, uint32_t *output_len)
{
    if(output == NULL || output_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(*output_len < content_len + 1) {
        *output_len = content_len + 1;
        return NOXTLS_RETURN_FAILED;
    }
    if(content != NULL && content_len > 0) {
        memcpy(output, content, content_len);
    }
    output[content_len] = content_type;
    *output_len = content_len + 1;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Parse TLS 1.3 inner plaintext after AEAD decryption (strip padding, read content type).
 * @param[in,out] plaintext     Decrypted inner plaintext; trailing zeros are padding.
 * @param[in,out] plaintext_len On input, decrypted length; on success, content length without type byte.
 * @param[out] content_type     Real record type from the final non-zero byte.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` or `NOXTLS_RETURN_BAD_DATA` on error.
 */
static noxtls_return_t tls13_extract_inner_plaintext(uint8_t *plaintext, uint32_t *plaintext_len, uint8_t *content_type)
{
    if(plaintext == NULL || plaintext_len == NULL || content_type == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    uint32_t len = *plaintext_len;
    while(len > 0 && plaintext[len - 1] == 0) {
        len--;
    }
    if(len == 0) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    *content_type = plaintext[len - 1];
    *plaintext_len = len - 1;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Free and clear the reassembly buffer for fragmented handshake records.
 * @param[in,out] ctx Context owning `handshake_buffer`.
 */
static void tls13_handshake_buffer_reset(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return;
    }
    if(ctx->handshake_buffer) {
        free(ctx->handshake_buffer);
        ctx->handshake_buffer = NULL;
    }
    ctx->handshake_buffer_len = 0;
    ctx->handshake_buffer_pos = 0;
}

/**
 * @brief Append raw bytes to the handshake reassembly buffer (compacts consumed prefix).
 * @param[in,out] ctx  Context buffer state.
 * @param[in] data     Bytes to append (may be NULL only if @p len is 0).
 * @param[in] len      Length of @p data.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` or `NOXTLS_RETURN_FAILED` on error.
 */
static noxtls_return_t tls13_handshake_buffer_append(tls13_context_t *ctx, const uint8_t *data, uint32_t len)
{
    if(ctx == NULL || (data == NULL && len > 0)) {
        return NOXTLS_RETURN_NULL;
    }
    if(len == 0) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(ctx->handshake_buffer_len < ctx->handshake_buffer_pos) {
        return NOXTLS_RETURN_FAILED;
    }
    uint32_t remaining = ctx->handshake_buffer_len - ctx->handshake_buffer_pos;
    if(len > UINT32_MAX - remaining) {
        return NOXTLS_RETURN_FAILED;
    }
    uint32_t new_len = remaining + len;
    uint8_t *new_buffer = (uint8_t*)realloc(ctx->handshake_buffer, new_len);
    if(new_buffer == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    /* Compact to front if we've consumed data */
    if(remaining > 0 && ctx->handshake_buffer_pos > 0) {
        memmove(new_buffer, new_buffer + ctx->handshake_buffer_pos, remaining);
    }
    memcpy(new_buffer + remaining, data, len);
    ctx->handshake_buffer = new_buffer;
    ctx->handshake_buffer_len = new_len;
    ctx->handshake_buffer_pos = 0;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Extract one complete handshake message from the reassembly buffer.
 *
 * Parses the 24-bit length field, allocates a copy of the message, and advances
 * the buffer position. Resets the buffer when fully consumed.
 *
 * @param[in,out] ctx     Context buffer state.
 * @param[out] out_msg    Allocated handshake message; caller must `free`.
 * @param[out] out_len    Length of the returned message.
 * @return `NOXTLS_RETURN_SUCCESS` when a full message is available; `NOXTLS_RETURN_FAILED`
 *         if fewer than four bytes or incomplete message; `NOXTLS_RETURN_NULL` on bad pointers.
 */
static noxtls_return_t tls13_handshake_buffer_get(tls13_context_t *ctx, uint8_t **out_msg, uint32_t *out_len)
{
    if(ctx == NULL || out_msg == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->handshake_buffer_len < ctx->handshake_buffer_pos) {
        return NOXTLS_RETURN_FAILED;
    }
    uint32_t available = ctx->handshake_buffer_len - ctx->handshake_buffer_pos;
    if(available < 4) {
        return NOXTLS_RETURN_FAILED;
    }
    const uint8_t *buf = ctx->handshake_buffer + ctx->handshake_buffer_pos;
    uint32_t hs_len = ((uint32_t)buf[1] << 16) | ((uint32_t)buf[2] << 8) | buf[3];
    uint32_t total_len = hs_len + 4;
    if(available < total_len) {
        return NOXTLS_RETURN_FAILED;
    }
    uint8_t *msg = (uint8_t*)malloc(total_len);
    if(msg == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(msg, buf, total_len);
    ctx->handshake_buffer_pos += total_len;
    if(ctx->handshake_buffer_pos >= ctx->handshake_buffer_len) {
        tls13_handshake_buffer_reset(ctx);
    }
    *out_msg = msg;
    *out_len = total_len;
    return NOXTLS_RETURN_SUCCESS;
}

#define TLS13_IMPL_RECORD_WORKSPACE_HALF  (TLS_MAX_RECORD_SIZE + 32)

/**
 * @brief Send a handshake message inside an encrypted TLS 1.3 or DTLS 1.3 record.
 *
 * Wraps @p msg as inner plaintext type handshake, then encrypts as application_data
 * (TLS) or uses the DTLS 1.3 record helper.
 *
 * @param[in,out] ctx     Context with handshake traffic keys installed.
 * @param[in] msg         Handshake message bytes.
 * @param[in] msg_len     Length of @p msg.
 * @return `NOXTLS_RETURN_SUCCESS` on success; error from inner plaintext build, encrypt, or send.
 */
static noxtls_return_t tls13_send_encrypted_handshake(tls13_context_t *ctx, const uint8_t *msg, uint32_t msg_len)
{
    uint32_t inner_len = TLS13_IMPL_RECORD_WORKSPACE_HALF;
    uint32_t encrypted_len = TLS13_IMPL_RECORD_WORKSPACE_HALF;
    uint8_t *inner = ctx->record_workspace;
    uint8_t *encrypted = ctx->record_workspace + TLS13_IMPL_RECORD_WORKSPACE_HALF;
    noxtls_return_t rc;

    if(ctx == NULL || msg == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls13_build_inner_plaintext(msg, msg_len, TLS_RECORD_HANDSHAKE, inner, &inner_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(tls13_is_dtls(ctx)) {
        return noxtls_tls13_send_dtls13_encrypted_record(ctx, 1, TLS_RECORD_HANDSHAKE, inner, inner_len, 1);
    }

    rc = noxtls_tls13_encrypt_record(ctx, TLS_RECORD_APPLICATION_DATA, inner, inner_len, encrypted, &encrypted_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return noxtls_tls_send_record(&ctx->base, TLS_RECORD_APPLICATION_DATA, encrypted, encrypted_len);
}

/**
 * @brief Receive the next handshake message (plaintext, encrypted, or from reassembly buffer).
 *
 * Reads records until a complete handshake message is available: handles middlebox CCS,
 * cleartext handshake records, and handshake carried in application_data ciphertext.
 *
 * @param[in,out] ctx     Context with appropriate read keys.
 * @param[out] out_msg    Allocated handshake message; caller must `free`.
 * @param[out] out_len    Length of the returned message.
 * @return `NOXTLS_RETURN_SUCCESS` on success; I/O, decrypt, or parse error codes otherwise.
 */
static noxtls_return_t tls13_recv_handshake_message(tls13_context_t *ctx, uint8_t **out_msg, uint32_t *out_len)
{
    tls_record_t record;
    noxtls_return_t rc;
    uint8_t content_type = 0;

    if(ctx == NULL || out_msg == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    /* Try to satisfy from buffered data first */
    rc = tls13_handshake_buffer_get(ctx, out_msg, out_len);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    while(1) {
        rc = noxtls_tls_recv_record(&ctx->base, &record);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(record.length > 0 && record.data == NULL) {
            return NOXTLS_RETURN_FAILED;
        }

        if(record.type == TLS_RECORD_CHANGE_CIPHER_SPEC) {
            if(record.data) free(record.data);
            /* TLS 1.3 middlebox compatibility CCS, ignore */
            continue;
        }

        if(record.type == TLS_RECORD_HANDSHAKE) {
            /* Append and return a single handshake noxtls_message */
            rc = tls13_handshake_buffer_append(ctx, record.data, record.length);
            if(record.data) free(record.data);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            rc = tls13_handshake_buffer_get(ctx, out_msg, out_len);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            continue;
        }

        if(record.type == TLS_RECORD_APPLICATION_DATA) {
            uint8_t *decrypted = (uint8_t*)malloc(record.length);
            uint32_t decrypted_len = record.length;
            if(decrypted == NULL) {
                if(record.data) free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            rc = noxtls_tls13_decrypt_record(ctx, record.data, record.length, decrypted, &decrypted_len);
            if(record.data) free(record.data);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_debug_printf("[TLS13_DEBUG] recv_handshake: decrypt rc=%d len=%u\n", rc, decrypted_len);
                NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_CRYPTO, NOXSIGHT_SEVERITY_ERROR,
                                NOXTLS_EVT_DECRYPT_FAIL, rc, record.length);
                free(decrypted);
                return rc;
            }
            rc = tls13_extract_inner_plaintext(decrypted, &decrypted_len, &content_type);
            if(rc != NOXTLS_RETURN_SUCCESS || content_type != TLS_RECORD_HANDSHAKE) {
                noxtls_debug_printf("[TLS13_DEBUG] recv_handshake: inner rc=%d type=%u len=%u\n",
                                      rc, content_type, decrypted_len);
                free(decrypted);
                return NOXTLS_RETURN_FAILED;
            }
            rc = tls13_handshake_buffer_append(ctx, decrypted, decrypted_len);
            free(decrypted);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            rc = tls13_handshake_buffer_get(ctx, out_msg, out_len);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            continue;
        }

        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
}

/**
 * @brief Initialize a TLS 1.3 / DTLS 1.3 context for client or server role.
 * @param[in,out] ctx  Context structure to zero and initialize.
 * @param[in] role     `TLS_ROLE_CLIENT` or `TLS_ROLE_SERVER`.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p ctx is NULL;
 *         `NOXTLS_RETURN_FAILED` or `NOXTLS_RETURN_NOT_ENOUGH_MEMORY` on setup failure.
 */
noxtls_return_t noxtls_tls13_context_init(tls13_context_t *ctx, tls_role_t role)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* TLS 1.3 uses 0x0303 in the record layer */
    if(noxtls_tls_context_init(&ctx->base, role, TLS_VERSION_1_2) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    
    memset(ctx->client_random, 0, sizeof(ctx->client_random));
    memset(ctx->server_random, 0, sizeof(ctx->server_random));
    ctx->cipher_suite = 0;
    memset(ctx->early_secret, 0, sizeof(ctx->early_secret));
    memset(ctx->handshake_secret, 0, sizeof(ctx->handshake_secret));
    memset(ctx->master_secret, 0, sizeof(ctx->master_secret));
    ctx->client_seq_num = 0;
    ctx->server_seq_num = 0;
    ctx->server_cert = NULL;
    ctx->server_cert_len = 0;
    ctx->server_cert_parsed = NULL;
    ctx->handshake_messages = NULL;
    ctx->handshake_messages_len = 0;
    ctx->handshake_buffer = NULL;
    ctx->handshake_buffer_len = 0;
    ctx->handshake_buffer_pos = 0;
    ctx->client_key_shares = NULL;
    ctx->client_key_shares_count = 0;
    ctx->server_key_share = NULL;
    ctx->ecdhe_ctx = NULL;
    ctx->server_name = NULL;
    ctx->server_name_len = 0;
    ctx->peer_connection_id_len = 0;
    ctx->own_connection_id_len = 0;
    ctx->record_workspace = NULL;
    ctx->handshake_workspace = NULL;
    ctx->channel_binding_first_finished_len = 0;

    {
        size_t ws_size = (size_t)TLS13_IMPL_RECORD_WORKSPACE_HALF * 2;
        ctx->record_workspace = (uint8_t*)noxtls_malloc(ws_size);
        if(ctx->record_workspace == NULL) {
            noxtls_tls_context_free(&ctx->base);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        ctx->handshake_workspace = (uint8_t*)noxtls_malloc(TLS_HANDSHAKE_WORKSPACE_SIZE);
        if(ctx->handshake_workspace == NULL) {
            noxtls_free(ctx->record_workspace);
            ctx->record_workspace = NULL;
            noxtls_tls_context_free(&ctx->base);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Release all resources owned by a TLS 1.3 context.
 * @param[in,out] ctx Context to free; safe to call with NULL.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p ctx is NULL.
 */
noxtls_return_t noxtls_tls13_context_free(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->record_workspace) {
        noxtls_free(ctx->record_workspace);
        ctx->record_workspace = NULL;
    }
    if(ctx->handshake_workspace) {
        memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        noxtls_free(ctx->handshake_workspace);
        ctx->handshake_workspace = NULL;
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
    if(ctx->handshake_buffer) {
        free(ctx->handshake_buffer);
        ctx->handshake_buffer = NULL;
    }
    ctx->handshake_buffer_len = 0;
    ctx->handshake_buffer_pos = 0;
    
    if(ctx->client_key_shares) {
        for(uint32_t i = 0; i < ctx->client_key_shares_count; i++) {
            if(ctx->client_key_shares[i].key_exchange) {
                free(ctx->client_key_shares[i].key_exchange);
            }
        }
        free(ctx->client_key_shares);
        ctx->client_key_shares = NULL;
    }
    
    if(ctx->server_key_share) {
        if(ctx->server_key_share->key_exchange) {
            free(ctx->server_key_share->key_exchange);
        }
        free(ctx->server_key_share);
        ctx->server_key_share = NULL;
    }

    if(ctx->ecdhe_ctx) {
        noxtls_tls_ecdhe_context_free((tls_ecdhe_context_t*)ctx->ecdhe_ctx);
        free(ctx->ecdhe_ctx);
        ctx->ecdhe_ctx = NULL;
    }
    
    /* Free extensions */
    noxtls_tls_extensions_free(&ctx->client_extensions);
    noxtls_tls_extensions_free(&ctx->server_extensions);
    
    noxtls_tls_context_free(&ctx->base);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Client: construct and send ClientHello (key shares, cipher suites, extensions).
 * @param[in,out] ctx Client context with transport initialized via `noxtls_tls_context_init`.
 * @return `NOXTLS_RETURN_SUCCESS` on success; error codes for DRBG, encoding, send, or memory failure.
 */
noxtls_return_t noxtls_tls13_send_client_hello(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    uint8_t *client_hello = ctx->handshake_workspace;
    if(client_hello == NULL) {
        client_hello = (uint8_t*)noxtls_malloc(1024 + 256);
        if(client_hello == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    uint8_t *key_share_entry = (ctx->handshake_workspace != NULL) ? (ctx->handshake_workspace + 1024) : (client_hello + 1024);
    uint32_t key_share_entry_len = 256;
    uint32_t offset = 0;
    drbg_state_t drbg_state;
    uint16_t cipher_suites[] = {
        TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
        TLS_CIPHER_SUITE_AES_256_GCM_SHA384,
        TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256
        /* Note: ARIA GCM suites for TLS 1.3 would need to be defined if supported */
    };
    uint16_t supported_groups[] = {
        TLS_NAMED_GROUP_SECP256R1,
        TLS_NAMED_GROUP_SECP384R1
    };
    uint16_t signature_algorithms[] = {
        0x0403, /* ecdsa_secp256r1_sha256 */
        0x0804, /* rsa_pss_rsae_sha256 */
        0x0807, /* ed25519 */
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
        0x0808, /* ed448 */
#endif
        0x0401, /* rsa_pkcs1_sha256 */
        0x0503, /* ecdsa_secp384r1_sha384 */
        0x0805  /* rsa_pss_rsae_sha384 */
    };
    tls_ecdhe_context_t *ecdhe_ctx = NULL;
    
    /* Generate client random */
    if(drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    if(drbg_generate(&drbg_state, ctx->client_random, sizeof(ctx->client_random) * 8u, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_debug_printf("[TLS13_DEBUG] client_random=");
    for(uint32_t i = 0; i < 32; i++) {
        noxtls_debug_printf("%02X", ctx->client_random[i]);
    }
    noxtls_debug_printf("\n");
    
    /* Build Client Hello noxtls_message */
    client_hello[offset++] = TLS_HANDSHAKE_CLIENT_HELLO;
    client_hello[offset++] = 0x00;  /* Length (3 bytes) - placeholder */
    client_hello[offset++] = 0x00;
    client_hello[offset++] = 0x00;
    
    /* Legacy version (for compatibility) */
    client_hello[offset++] = 0x03;
    client_hello[offset++] = 0x03;
    
    /* Random (32 bytes) */
    memcpy(client_hello + offset, ctx->client_random, 32);
    offset += 32;
    
    /* Legacy session ID length (1 byte) */
    uint8_t session_id[32];
    if(drbg_generate(&drbg_state, session_id, sizeof(session_id) * 8u, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    client_hello[offset++] = (uint8_t)sizeof(session_id);
    memcpy(client_hello + offset, session_id, sizeof(session_id));
    offset += sizeof(session_id);
    
    /* Cipher suites length (2 bytes) */
    uint16_t cipher_suites_len = sizeof(cipher_suites);
    client_hello[offset++] = (cipher_suites_len >> 8) & 0xFF;
    client_hello[offset++] = cipher_suites_len & 0xFF;
    
    /* Cipher suites (network byte order) */
    for(uint32_t i = 0; i < sizeof(cipher_suites) / sizeof(cipher_suites[0]); i++) {
        client_hello[offset++] = (cipher_suites[i] >> 8) & 0xFF;
        client_hello[offset++] = cipher_suites[i] & 0xFF;
    }
    
    /* Legacy compression methods length (1 byte) */
    client_hello[offset++] = 0x01;
    client_hello[offset++] = 0x00;  /* NULL compression */
    
    /* Extensions length (2 bytes) - placeholder */
    uint32_t extensions_start = offset;
    client_hello[offset++] = 0x00;
    client_hello[offset++] = 0x00;
    
    /* Ensure ECDHE context and key share */
    if(ctx->ecdhe_ctx == NULL) {
        ecdhe_ctx = (tls_ecdhe_context_t*)malloc(sizeof(tls_ecdhe_context_t));
        if(ecdhe_ctx == NULL) {
            if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        if(noxtls_tls_ecdhe_context_init(ecdhe_ctx, TLS_NAMED_GROUP_SECP256R1) != NOXTLS_RETURN_SUCCESS) {
            free(ecdhe_ctx);
            if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        if(noxtls_tls_ecdhe_generate_ephemeral_key(ecdhe_ctx) != NOXTLS_RETURN_SUCCESS) {
            noxtls_tls_ecdhe_context_free(ecdhe_ctx);
            free(ecdhe_ctx);
            if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        ctx->ecdhe_ctx = ecdhe_ctx;
    } else {
        ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
    }

    if(noxtls_tls13_key_share_encode(ecdhe_ctx, key_share_entry, &key_share_entry_len) != NOXTLS_RETURN_SUCCESS) {
        if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    if(key_share_entry_len >= 8) {
        noxtls_debug_printf("[TLS13_DEBUG] client_key_share: group=0x%04X key[0..3]=%02X%02X%02X%02X\n",
                              ecdhe_ctx->named_group,
                              key_share_entry[4], key_share_entry[5], key_share_entry[6], key_share_entry[7]);
    }

    if(ctx->client_key_shares) {
        for(uint32_t i = 0; i < ctx->client_key_shares_count; i++) {
            if(ctx->client_key_shares[i].key_exchange) {
                free(ctx->client_key_shares[i].key_exchange);
            }
        }
        free(ctx->client_key_shares);
        ctx->client_key_shares = NULL;
        ctx->client_key_shares_count = 0;
    }
    ctx->client_key_shares = (tls13_key_share_entry_t*)malloc(sizeof(tls13_key_share_entry_t));
    if(ctx->client_key_shares == NULL) {
        if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    ctx->client_key_shares_count = 1;
    ctx->client_key_shares[0].group = ecdhe_ctx->named_group;
    ctx->client_key_shares[0].key_exchange_len = (uint16_t)(key_share_entry_len - 4);
    ctx->client_key_shares[0].key_exchange = (uint8_t*)malloc(ctx->client_key_shares[0].key_exchange_len);
    if(ctx->client_key_shares[0].key_exchange == NULL) {
        free(ctx->client_key_shares);
        ctx->client_key_shares = NULL;
        if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(ctx->client_key_shares[0].key_exchange, key_share_entry + 4, ctx->client_key_shares[0].key_exchange_len);
    
    /* Server Name (SNI) */
    if(ctx->server_name != NULL && ctx->server_name_len > 0) {
        uint32_t ext_start = offset;
        uint32_t sni_list_len = 1 + 2 + ctx->server_name_len;
        uint32_t sni_ext_len = 2 + sni_list_len;
        client_hello[offset++] = (TLS_EXTENSION_SERVER_NAME >> 8) & 0xFF;
        client_hello[offset++] = TLS_EXTENSION_SERVER_NAME & 0xFF;
        client_hello[offset++] = (sni_ext_len >> 8) & 0xFF;
        client_hello[offset++] = sni_ext_len & 0xFF;
        client_hello[offset++] = (sni_list_len >> 8) & 0xFF;
        client_hello[offset++] = sni_list_len & 0xFF;
        client_hello[offset++] = 0x00; /* host_name */
        client_hello[offset++] = (ctx->server_name_len >> 8) & 0xFF;
        client_hello[offset++] = ctx->server_name_len & 0xFF;
        memcpy(client_hello + offset, ctx->server_name, ctx->server_name_len);
        offset += ctx->server_name_len;
        (void)ext_start;
    }

    /* Supported Versions */
    client_hello[offset++] = (TLS_EXTENSION_SUPPORTED_VERSIONS >> 8) & 0xFF;
    client_hello[offset++] = TLS_EXTENSION_SUPPORTED_VERSIONS & 0xFF;
    client_hello[offset++] = 0x00;
    client_hello[offset++] = 0x05;
    client_hello[offset++] = 0x04;
    client_hello[offset++] = 0x03;
    client_hello[offset++] = 0x04;
    client_hello[offset++] = 0x03;
    client_hello[offset++] = 0x03;

    /* Supported Groups */
    client_hello[offset++] = (TLS_EXTENSION_SUPPORTED_GROUPS >> 8) & 0xFF;
    client_hello[offset++] = TLS_EXTENSION_SUPPORTED_GROUPS & 0xFF;
    uint16_t groups_len = sizeof(supported_groups);
    client_hello[offset++] = (uint8_t)((groups_len + 2) >> 8);
    client_hello[offset++] = (uint8_t)((groups_len + 2) & 0xFF);
    client_hello[offset++] = (groups_len >> 8) & 0xFF;
    client_hello[offset++] = groups_len & 0xFF;
    for(uint32_t i = 0; i < sizeof(supported_groups) / sizeof(supported_groups[0]); i++) {
        client_hello[offset++] = (supported_groups[i] >> 8) & 0xFF;
        client_hello[offset++] = supported_groups[i] & 0xFF;
    }

    /* Signature Algorithms */
    client_hello[offset++] = (TLS_EXTENSION_SIGNATURE_ALGORITHMS >> 8) & 0xFF;
    client_hello[offset++] = TLS_EXTENSION_SIGNATURE_ALGORITHMS & 0xFF;
    uint16_t sig_len = sizeof(signature_algorithms);
    client_hello[offset++] = (uint8_t)((sig_len + 2) >> 8);
    client_hello[offset++] = (uint8_t)((sig_len + 2) & 0xFF);
    client_hello[offset++] = (sig_len >> 8) & 0xFF;
    client_hello[offset++] = sig_len & 0xFF;
    for(uint32_t i = 0; i < sizeof(signature_algorithms) / sizeof(signature_algorithms[0]); i++) {
        client_hello[offset++] = (signature_algorithms[i] >> 8) & 0xFF;
        client_hello[offset++] = signature_algorithms[i] & 0xFF;
    }

    /* Key Share */
    client_hello[offset++] = (TLS_EXTENSION_KEY_SHARE >> 8) & 0xFF;
    client_hello[offset++] = TLS_EXTENSION_KEY_SHARE & 0xFF;
    uint16_t key_share_list_len = (uint16_t)key_share_entry_len;
    uint16_t key_share_ext_len = (uint16_t)(key_share_entry_len + 2);
    client_hello[offset++] = (key_share_ext_len >> 8) & 0xFF;
    client_hello[offset++] = key_share_ext_len & 0xFF;
    client_hello[offset++] = (key_share_list_len >> 8) & 0xFF;
    client_hello[offset++] = key_share_list_len & 0xFF;
    memcpy(client_hello + offset, key_share_entry, key_share_entry_len);
    offset += key_share_entry_len;

    /* Update extensions length */
    uint16_t extensions_len = offset - extensions_start - 2;
    client_hello[extensions_start] = (extensions_len >> 8) & 0xFF;
    client_hello[extensions_start + 1] = extensions_len & 0xFF;
    
    /* Update handshake noxtls_message length */
    uint32_t handshake_len = offset - 4;
    client_hello[1] = (handshake_len >> 16) & 0xFF;
    client_hello[2] = (handshake_len >> 8) & 0xFF;
    client_hello[3] = handshake_len & 0xFF;
    noxtls_debug_printf("[TLS13_DEBUG] client_hello: len=%u\n", handshake_len + 4);
    
    /* Append to handshake transcript */
    tls13_append_handshake_message(ctx, client_hello, offset);

    noxtls_debug_printf("[TLS13_DEBUG] client_hello hex:\n");
    for(uint32_t i = 0; i < offset; i++) {
        noxtls_debug_printf("%02X", client_hello[i]);
        if(((i + 1) & 31) == 0) {
            noxtls_debug_printf("\n");
        }
    }
    if(offset % 32 != 0) {
        noxtls_debug_printf("\n");
    }

    /* Send via record layer */
    {
        noxtls_return_t send_rc = noxtls_tls_send_record(&ctx->base, TLS_RECORD_HANDSHAKE, client_hello, offset);
        if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        if(send_rc == NOXTLS_RETURN_SUCCESS) {
            NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_HANDSHAKE, NOXSIGHT_SEVERITY_INFO,
                            NOXTLS_EVT_CLIENT_HELLO_SENT, offset, ctx->cipher_suite);
        } else {
            NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_IO, NOXSIGHT_SEVERITY_ERROR,
                            NOXTLS_EVT_INTERNAL_ERROR, NOXTLS_EVT_CLIENT_HELLO_SENT, send_rc);
        }
        return send_rc;
    }
}

/**
 * @brief Client: receive and process ServerHello (version, random, cipher suite, key share).
 * @param[in,out] ctx Client context; updates transcript and derives handshake keys on success.
 * @return `NOXTLS_RETURN_SUCCESS` on success; I/O, parse, or key-exchange error codes otherwise.
 */
noxtls_return_t noxtls_tls13_recv_server_hello(tls13_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    rc = noxtls_tls_recv_record(&ctx->base, &record);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_IO, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_INTERNAL_ERROR, NOXTLS_EVT_SERVER_HELLO_RECV, rc);
        return rc;
    }
    if(record.length > 0 && record.data == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: record type=%u len=%u\n", record.type, record.length);
    if(record.type != TLS_RECORD_HANDSHAKE || record.length < 42) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: hs_type=0x%02X\n", record.data[0]);
    if(record.data[0] != TLS_HANDSHAKE_SERVER_HELLO) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    if(record.length >= 4) {
        uint32_t hs_len = ((uint32_t)record.data[1] << 16) | ((uint32_t)record.data[2] << 8) | record.data[3];
        noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: hs_len=%u\n", hs_len);
    }
    
    /* Append to transcript */
    tls13_append_handshake_message(ctx, record.data, record.length);
    noxtls_debug_printf("[TLS13_DEBUG] server_hello hex:\n");
    for(uint32_t i = 0; i < record.length; i++) {
        noxtls_debug_printf("%02X", record.data[i]);
        if(((i + 1) & 31) == 0) {
            noxtls_debug_printf("\n");
        }
    }
    if((record.length & 31) != 0) {
        noxtls_debug_printf("\n");
    }

    /* Parse Server Hello */
    uint32_t offset = 4; /* Skip handshake header */
    if(offset + 2 + 32 + 1 > record.length) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    offset += 2; /* legacy_version */
    memcpy(ctx->server_random, record.data + offset, 32);
    noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: server_random[0..3]=%02X%02X%02X%02X\n",
                          ctx->server_random[0], ctx->server_random[1], ctx->server_random[2], ctx->server_random[3]);
    {
        static const uint8_t hrr_random[32] = {
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
        };
        if(memcmp(ctx->server_random, hrr_random, sizeof(hrr_random)) == 0) {
            noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: detected HelloRetryRequest (HRR)\n");
        }
    }
    offset += 32;

    uint8_t session_id_len = record.data[offset++];
    if(offset + session_id_len + 2 + 1 + 2 > record.length) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    offset += session_id_len;

    ctx->cipher_suite = (record.data[offset] << 8) | record.data[offset + 1];
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_HANDSHAKE, NOXSIGHT_SEVERITY_INFO,
                    NOXTLS_EVT_SERVER_HELLO_RECV, ctx->cipher_suite, record.length);
    noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: cipher_suite=0x%04X\n", ctx->cipher_suite);
    offset += 2;

    offset += 1; /* legacy compression method */

    if(offset + 2 > record.length) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }

    /* Parse extensions */
    noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: extensions_len=%u\n", (unsigned)(record.length - offset));
    if(noxtls_tls_parse_extensions(record.data + offset, record.length - offset, &ctx->server_extensions) != NOXTLS_RETURN_SUCCESS) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }

    tls_extension_t *ext = NULL;
    if(noxtls_tls_find_extension(&ctx->server_extensions, TLS_EXTENSION_SUPPORTED_VERSIONS, &ext) == NOXTLS_RETURN_SUCCESS) {
        if(ext == NULL || ext->length != 2 || ext->data == NULL) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        uint16_t negotiated = (ext->data[0] << 8) | ext->data[1];
        noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: supported_versions=0x%04X\n", negotiated);
        if(negotiated != TLS_VERSION_1_3) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
    } else {
        noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: supported_versions not found\n");
    }

    if(noxtls_tls_find_extension(&ctx->server_extensions, TLS_EXTENSION_KEY_SHARE, &ext) == NOXTLS_RETURN_SUCCESS) {
        if(ext == NULL || ext->length < 4 || ext->data == NULL) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        uint16_t group = (ext->data[0] << 8) | ext->data[1];
        uint16_t key_len = (ext->data[2] << 8) | ext->data[3];
        noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: key_share group=0x%04X len=%u\n", group, key_len);
        if(ext->length >= 8) {
            noxtls_debug_printf("[TLS13_DEBUG] server_key_share: key[0..3]=%02X%02X%02X%02X\n",
                                  ext->data[4], ext->data[5], ext->data[6], ext->data[7]);
        }
        if(4 + key_len > ext->length) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        if(ctx->server_key_share) {
            if(ctx->server_key_share->key_exchange) {
                free(ctx->server_key_share->key_exchange);
            }
            free(ctx->server_key_share);
            ctx->server_key_share = NULL;
        }
        ctx->server_key_share = (tls13_key_share_entry_t*)malloc(sizeof(tls13_key_share_entry_t));
        if(ctx->server_key_share == NULL) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        ctx->server_key_share->group = group;
        ctx->server_key_share->key_exchange_len = key_len;
        ctx->server_key_share->key_exchange = (uint8_t*)malloc(key_len);
        if(ctx->server_key_share->key_exchange == NULL) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(ctx->server_key_share->key_exchange, ext->data + 4, key_len);
    } else {
        noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: key_share not found\n");
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }

    if(record.data) free(record.data);

    if(ctx->ecdhe_ctx == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    tls_ecdhe_context_t *ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
    rc = noxtls_tls13_process_server_key_share(ctx, ecdhe_ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: process_key_share rc=%d\n", rc);
        return rc;
    }

    if(ecdhe_ctx->shared_secret == NULL || ecdhe_ctx->shared_secret_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    rc = tls13_derive_handshake_keys(ctx, ecdhe_ctx->shared_secret, ecdhe_ctx->shared_secret_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: derive_handshake_keys rc=%d\n", rc);
    }
    return rc;
}

/**
 * @brief Client: receive EncryptedExtensions handshake message.
 * @param[in,out] ctx Client context with handshake traffic keys active.
 * @return `NOXTLS_RETURN_SUCCESS` on success; error from receive or transcript update.
 */
noxtls_return_t noxtls_tls13_recv_encrypted_extensions(tls13_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls13_recv_handshake_message(ctx, &msg, &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(msg_len < 4 || msg[0] != TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }

    /* Append to transcript */
    tls13_append_handshake_message(ctx, msg, msg_len);

    /* Parse encrypted extensions (extensions length at offset 4, then extension data) */
    if(msg_len >= 6) {
        uint32_t ext_len = ((uint32_t)msg[4] << 8) | msg[5];
        if(ext_len > 0 && 6u + ext_len <= msg_len) {
            noxtls_tls_parse_extensions(msg + 6, ext_len, &ctx->server_extensions);
        }
    }

    free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Client: receive and parse the server Certificate message.
 * @param[in,out] ctx Client context; stores DER chain in context for verification.
 * @return `NOXTLS_RETURN_SUCCESS` on success; receive, parse, or memory error otherwise.
 */
noxtls_return_t noxtls_tls13_recv_certificate(tls13_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    uint32_t cert_list_len;
    uint32_t cert_len;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls13_recv_handshake_message(ctx, &msg, &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_IO, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_INTERNAL_ERROR, NOXTLS_EVT_CERTIFICATE_RECV, rc);
        return rc;
    }

    if(msg_len < 8 || msg[0] != TLS_HANDSHAKE_CERTIFICATE) {
        free(msg);
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_CERT_PARSE_FAIL, msg_len, 0u);
        return NOXTLS_RETURN_FAILED;
    }

    /* Append to transcript */
    tls13_append_handshake_message(ctx, msg, msg_len);

    /* Parse Certificate noxtls_message (TLS 1.3 format); need at least 4 bytes handshake header + 1 byte cert_request_context_len */
    uint32_t offset = 4;
    if(msg_len < 5u || offset >= msg_len) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    uint8_t cert_request_context_len = msg[offset++];
    if(offset + cert_request_context_len + 3 > msg_len) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    offset += cert_request_context_len;

    cert_list_len = (msg[offset] << 16) | (msg[offset + 1] << 8) | msg[offset + 2];
    offset += 3;
    if(cert_list_len < 3 || offset + cert_list_len > msg_len) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }

    cert_len = (msg[offset] << 16) | (msg[offset + 1] << 8) | msg[offset + 2];
    offset += 3;
    if(cert_len == 0 || offset + cert_len > msg_len) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }

    if(ctx->server_cert) {
        free(ctx->server_cert);
    }
    ctx->server_cert = (uint8_t*)malloc(cert_len);
    if(ctx->server_cert == NULL) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(ctx->server_cert, msg + offset, cert_len);
    ctx->server_cert_len = cert_len;

    if(ctx->server_cert_parsed) {
        noxtls_x509_certificate_free((x509_certificate_t*)ctx->server_cert_parsed);
        free(ctx->server_cert_parsed);
        ctx->server_cert_parsed = NULL;
    }

    x509_certificate_t *parsed_cert = (x509_certificate_t*)malloc(sizeof(x509_certificate_t));
    if(parsed_cert) {
        noxtls_x509_certificate_init(parsed_cert);
        noxtls_return_t parse_rc = noxtls_x509_certificate_parse_der(parsed_cert, ctx->server_cert, ctx->server_cert_len);
        if(parse_rc == NOXTLS_RETURN_SUCCESS) {
            ctx->server_cert_parsed = parsed_cert;
        } else {
            NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                            NOXTLS_EVT_CERT_PARSE_FAIL, ctx->server_cert_len, 1u);
            noxtls_x509_certificate_free(parsed_cert);
            free(parsed_cert);
            free(msg);
            return parse_rc;
        }
    }

    /* Verify certificate signature: use issuer from chain if present, else self-signature */
    if(ctx->server_cert_parsed != NULL) {
        uint32_t entry_offset = offset + cert_len;  /* After first cert data */
        x509_certificate_t *issuer_cert = NULL;
        if(entry_offset + 2 <= msg_len) {
            uint16_t ext_len = (msg[entry_offset] << 8) | msg[entry_offset + 1];
            entry_offset += 2 + ext_len;  /* Skip first entry's extensions */
        }
        if(entry_offset + 3 <= msg_len) {
            uint32_t next_len = (msg[entry_offset] << 16) | (msg[entry_offset + 1] << 8) | msg[entry_offset + 2];
            if(next_len >= 3 && entry_offset + 3 + next_len <= msg_len) {
                uint32_t next_cert_len = (msg[entry_offset + 3] << 16) | (msg[entry_offset + 4] << 8) | msg[entry_offset + 5];
                if(next_cert_len > 0 && entry_offset + 6 + next_cert_len <= msg_len) {
                    issuer_cert = (x509_certificate_t*)malloc(sizeof(x509_certificate_t));
                    if(issuer_cert != NULL) {
                        noxtls_x509_certificate_init(issuer_cert);
                        if(noxtls_x509_certificate_parse_der(issuer_cert, msg + entry_offset + 6, next_cert_len) != NOXTLS_RETURN_SUCCESS) {
                            noxtls_x509_certificate_free(issuer_cert);
                            free(issuer_cert);
                            issuer_cert = NULL;
                        }
                    }
                }
            }
        }
        if(issuer_cert == NULL) {
            issuer_cert = (x509_certificate_t*)ctx->server_cert_parsed;  /* Self-signature check */
        }
        rc = noxtls_x509_certificate_verify_signature((x509_certificate_t*)ctx->server_cert_parsed, issuer_cert);
        if(issuer_cert != NULL && issuer_cert != ctx->server_cert_parsed) {
            noxtls_x509_certificate_free(issuer_cert);
            free(issuer_cert);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(msg);
            NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                            NOXTLS_EVT_CERT_VERIFY_FAIL, rc, 1u);
            return rc;
        }
        /* Client: verify server cert is valid for the requested hostname (SAN or CN) */
        if(ctx->server_name != NULL && ctx->server_name_len > 0) {
            rc = noxtls_x509_certificate_matches_hostname((x509_certificate_t*)ctx->server_cert_parsed,
                (const char*)ctx->server_name, ctx->server_name_len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                free(msg);
                NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                                NOXTLS_EVT_CERT_VERIFY_FAIL, rc, 2u);
                return rc;
            }
        }
    }

    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_INFO,
                    NOXTLS_EVT_CERTIFICATE_RECV, ctx->server_cert_len, 0u);
    free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Client: receive CertificateVerify and verify the server signature over the transcript.
 * @param[in,out] ctx Client context with server certificate loaded.
 * @return `NOXTLS_RETURN_SUCCESS` on valid signature; verification or I/O error otherwise.
 */
noxtls_return_t noxtls_tls13_recv_certificate_verify(tls13_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls13_recv_handshake_message(ctx, &msg, &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_IO, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_INTERNAL_ERROR, NOXTLS_EVT_VERIFY_SIG_FAIL, rc);
        return rc;
    }

    if(msg_len < 4 || msg[0] != TLS_HANDSHAKE_CERTIFICATE_VERIFY) {
        free(msg);
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_VERIFY_SIG_FAIL, 1u, msg_len);
        return NOXTLS_RETURN_FAILED;
    }

    /* Verify Certificate Verify signature before appending (signature is over transcript excluding this noxtls_message) */
    if(msg_len >= 8 && ctx->server_cert_parsed != NULL) {
        uint16_t sig_scheme = (msg[4] << 8) | msg[5];
        uint16_t sig_len = (msg[6] << 8) | msg[7];
        if(8u + sig_len > msg_len) {
            free(msg);
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_hash_algos_t hash_algo;
        uint32_t hash_len;
        uint32_t key_len;
        noxtls_return_t rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(msg);
            return rc;
        }
        uint8_t transcript_hash[64];
        uint32_t transcript_len = sizeof(transcript_hash);
        rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                                 transcript_hash, &transcript_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(msg);
            return rc;
        }
        /* Signed content per RFC 8446: 64*0x20 + "TLS 1.3, server CertificateVerify" + 0x00 + Hash */
        static const char ctx_str[] = "TLS 1.3;
        static const char server CertificateVerify";
        uint8_t to_verify[64 + sizeof(ctx_str) + 1 + 64];
        uint32_t to_verify_len = 0;
        memset(to_verify, 0x20, 64);
        to_verify_len = 64;
        memcpy(to_verify + to_verify_len, ctx_str, sizeof(ctx_str));
        to_verify_len += sizeof(ctx_str);
        to_verify[to_verify_len++] = 0x00;
        memcpy(to_verify + to_verify_len, transcript_hash, transcript_len);
        to_verify_len += transcript_len;

        x509_certificate_t *cert = (x509_certificate_t*)ctx->server_cert_parsed;
        if(cert->rsa_modulus != NULL && cert->rsa_exponent != NULL && sig_scheme == TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256) {
            /* rsa_pss_rsae_sha256 */
            uint32_t key_bytes = cert->rsa_modulus_len;
            rsa_key_size_t key_size = (key_bytes == 128) ? RSA_1024_BIT : (key_bytes == 256) ? RSA_2048_BIT :
                                     (key_bytes == 384) ? RSA_3072_BIT : (key_bytes == 512) ? RSA_4096_BIT : RSA_1024_BIT;
            if(key_bytes != 128 && key_bytes != 256 && key_bytes != 384 && key_bytes != 512) {
                free(msg);
                return NOXTLS_RETURN_FAILED;
            }
            rsa_key_t rsa_key;
            rc = noxtls_rsa_key_init(&rsa_key, key_size);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                free(msg);
                return rc;
            }
            memcpy(rsa_key.n, cert->rsa_modulus, cert->rsa_modulus_len);
            memcpy(rsa_key.e, cert->rsa_exponent, cert->rsa_exponent_len);
            rc = noxtls_rsa_verify_pss(&rsa_key, to_verify, to_verify_len, msg + 8, sig_len, NOXTLS_HASH_SHA_256);
            noxtls_rsa_key_free(&rsa_key);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                free(msg);
                NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                                NOXTLS_EVT_VERIFY_SIG_FAIL, 2u, rc);
                return NOXTLS_RETURN_FAILED;
            }
        } else {
            /* ECDSA / other not implemented in this path */
            free(msg);
            NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                            NOXTLS_EVT_VERIFY_SIG_FAIL, 3u, sig_scheme);
            return NOXTLS_RETURN_FAILED;
        }
    }

    /* Append to transcript after verification */
    tls13_append_handshake_message(ctx, msg, msg_len);

    free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Client: receive server Finished and verify verify_data against the transcript.
 * @param[in,out] ctx Client context; switches to application traffic secret derivation after verify.
 * @return `NOXTLS_RETURN_SUCCESS` on success; MAC mismatch or handshake error otherwise.
 */
noxtls_return_t noxtls_tls13_recv_finished(tls13_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    uint8_t transcript_hash[64];
    uint32_t transcript_len = sizeof(transcript_hash);
    uint8_t finished_key[64];
    uint32_t finished_key_len;
    uint8_t verify_data[64];
    uint32_t verify_len;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls13_recv_handshake_message(ctx, &msg, &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(msg_len < 4 || msg[0] != TLS_HANDSHAKE_FINISHED) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }

    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(msg);
        return rc;
    }

    rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                             transcript_hash, &transcript_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(msg);
        return rc;
    }

    finished_key_len = hash_len;
    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->server_handshake_traffic_secret, hash_len,
                                 (const uint8_t*)"finished", 8, NULL, 0,
                                 finished_key, finished_key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(msg);
        return rc;
    }

    verify_len = hash_len;
    rc = hmac_compute(hash_algo, finished_key, hash_len, transcript_hash, transcript_len,
                      verify_data, &verify_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(msg);
        return rc;
    }

    if(msg_len < 4 + verify_len || noxtls_secret_memcmp(msg + 4, verify_data, verify_len) != 0) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }

    /* RFC 5929: store first Finished verify_data for tls-unique channel binding (TLS 1.3: server sends first) */
    if(ctx->channel_binding_first_finished_len == 0 && verify_len <= sizeof(ctx->channel_binding_first_finished)) {
        memcpy(ctx->channel_binding_first_finished, msg + 4, verify_len);
        ctx->channel_binding_first_finished_len = verify_len;
    }

    /* Append server Finished to transcript */
    tls13_append_handshake_message(ctx, msg, msg_len);

    free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Client: send Finished with verify_data for the current transcript.
 * @param[in,out] ctx Client context after server Finished has been processed.
 * @return `NOXTLS_RETURN_SUCCESS` on success; error from Finished construction or encrypted send.
 */
noxtls_return_t noxtls_tls13_send_finished(tls13_context_t *ctx)
{
    uint8_t finished[80];
    uint32_t offset = 0;
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    uint8_t transcript_hash[64];
    uint32_t transcript_len = sizeof(transcript_hash);
    uint8_t finished_key[64];
    uint32_t finished_key_len;
    uint8_t verify_data[64];
    uint32_t verify_len;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                             transcript_hash, &transcript_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    finished_key_len = hash_len;
    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->client_handshake_traffic_secret, hash_len,
                                 (const uint8_t*)"finished", 8, NULL, 0,
                                 finished_key, finished_key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    verify_len = hash_len;
    rc = hmac_compute(hash_algo, finished_key, hash_len, transcript_hash, transcript_len,
                      verify_data, &verify_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* Build Finished noxtls_message */
    finished[offset++] = TLS_HANDSHAKE_FINISHED;
    finished[offset++] = 0x00;
    finished[offset++] = 0x00;
    finished[offset++] = (uint8_t)verify_len;
    memcpy(finished + offset, verify_data, verify_len);
    offset += verify_len;

    rc = tls13_send_encrypted_handshake(ctx, finished, offset);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* Append client Finished to transcript */
    tls13_append_handshake_message(ctx, finished, offset);

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Client: run the full TLS 1.3 handshake through application key installation.
 *
 * Sends ClientHello, receives server flight, derives application secrets, sends client Finished,
 * and installs application traffic keys.
 *
 * @param[in,out] ctx Initialized client context.
 * @return `NOXTLS_RETURN_SUCCESS` when application keys are ready; error from any handshake step.
 */
noxtls_return_t noxtls_tls13_connect(tls13_context_t *ctx)
{
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.role != TLS_ROLE_CLIENT) {
        return NOXTLS_RETURN_FAILED;
    }
    
    ctx->base.state = TLS_STATE_HANDSHAKING;
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_START);
    
    noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: send_client_hello...\n");
    /* Send Client Hello */
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_SEND_CH);
    rc = noxtls_tls13_send_client_hello(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_send_client_hello rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_CH, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_CH, rc);
    
    /* Receive Server Hello */
    noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: recv_server_hello...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_RECV_SH);
    rc = noxtls_tls13_recv_server_hello(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_recv_server_hello rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_SH, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_SH, rc);
    
    /* Receive Encrypted Extensions */
    noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: recv_encrypted_extensions...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_RECV_ENC_EXT);
    rc = noxtls_tls13_recv_encrypted_extensions(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_recv_encrypted_extensions rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_ENC_EXT, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_ENC_EXT, rc);
    
    /* Receive Certificate */
    noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: recv_certificate...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_VERIFY_CERT);
    rc = noxtls_tls13_recv_certificate(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_recv_certificate rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_VERIFY_CERT, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_VERIFY_CERT, rc);
    
    /* Receive Certificate Verify */
    noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: recv_certificate_verify...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_RECV_CERT_VERIFY);
    rc = noxtls_tls13_recv_certificate_verify(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_recv_certificate_verify rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_CERT_VERIFY, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_CERT_VERIFY, rc);
    
    /* Receive Finished */
    noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: recv_finished...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_RECV_FINISHED);
    rc = noxtls_tls13_recv_finished(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_recv_finished rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_FINISHED, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_FINISHED, rc);

    /* Derive application traffic secrets (uses transcript incl. server Finished) */
    noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: derive_application_secrets...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_KEY_SCHEDULE);
    rc = tls13_derive_application_secrets(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] tls13_derive_application_secrets rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_KEY_SCHEDULE, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_KEY_SCHEDULE, rc);
    
    /* Send Finished */
    noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: send_finished...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_SEND_FINISHED);
    rc = noxtls_tls13_send_finished(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_send_finished rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_FINISHED, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_FINISHED, rc);

    /* Install application keys after sending client Finished */
    noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: install_application_keys...\n");
    rc = tls13_install_application_keys(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] tls13_install_application_keys rc=%d\n", rc);
        return rc;
    }
    
    ctx->base.state = TLS_STATE_CONNECTED;
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_CONNECTED);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Server: receive and parse ClientHello (cipher suites, groups, key shares, extensions).
 * @param[in,out] ctx Server context; selects cipher suite and stores client random and shares.
 * @return `NOXTLS_RETURN_SUCCESS` on success; I/O or parse error otherwise.
 */
noxtls_return_t noxtls_tls13_recv_client_hello(tls13_context_t *ctx)
{
    tls_record_t record;
    uint32_t offset;
    uint16_t version;
    uint8_t session_id_len;
    uint16_t cipher_suites_len;
    uint8_t compression_methods_len;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Check if we have a pending Client Hello from version negotiation */
    if(ctx->base.pending_client_hello != NULL && ctx->base.pending_client_hello_len > 0) {
        uint8_t use_pending = 1;
        (void)use_pending;
        record.type = TLS_RECORD_HANDSHAKE;
        record.version = TLS_VERSION_1_3;  /* Legacy version for TLS 1.3 */
        (void)record.version;
        record.length = ctx->base.pending_client_hello_len;
        record.data = (uint8_t*)malloc(record.length);
        if(record.length > 0 && record.data == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(record.data, ctx->base.pending_client_hello, record.length);
    } else {
        noxtls_return_t rc = noxtls_tls_recv_record(&ctx->base, &record);
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
    
    offset = 4;  /* Skip handshake header */
    
    /* Version */
    version = (record.data[offset] << 8) | record.data[offset + 1];
    (void)version;
    offset += 2;
    
    /* Client Random (32 bytes) */
    memcpy(ctx->client_random, record.data + offset, 32);
    offset += 32;
    
    /* Session ID length */
    session_id_len = record.data[offset++];
    offset += session_id_len;  /* Skip session ID */
    
    /* Cipher suites length */
    cipher_suites_len = (record.data[offset] << 8) | record.data[offset + 1];
    offset += 2;
    {
        static const uint16_t supported_suites[] = {
            TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
            TLS_CIPHER_SUITE_AES_256_GCM_SHA384,
            TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256
        };
        uint32_t n = cipher_suites_len >> 1;
        ctx->cipher_suite = 0;
        for(uint32_t i = 0; i < n; i++) {
            uint16_t suite = (record.data[offset + (i * 2)] << 8) | record.data[offset + (i << 1) + 1];
            for(uint32_t j = 0; j < sizeof(supported_suites) / sizeof(supported_suites[0]); j++) {
                if(suite == supported_suites[j]) {
                    ctx->cipher_suite = suite;
                    break;
                }
            }
            if(ctx->cipher_suite != 0) break;
        }
        if(ctx->cipher_suite == 0) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
    }
    offset += cipher_suites_len;
    
    /* Compression methods length */
    compression_methods_len = record.data[offset++];
    offset += compression_methods_len;
    
    /* Parse extensions (especially key_share extension) */
    if(offset < record.length) {
        uint32_t extensions_len = record.length - offset;
        if(extensions_len >= 2) {
            noxtls_return_t rc = noxtls_tls_parse_extensions(record.data + offset, extensions_len, &ctx->client_extensions);
            if(rc == NOXTLS_RETURN_SUCCESS && ctx->client_extensions.key_share != NULL) {
                /* Extract client key shares for key exchange */
                if(ctx->client_key_shares) {
                    for(uint32_t i = 0; i < ctx->client_key_shares_count; i++) {
                        if(ctx->client_key_shares[i].key_exchange) {
                            free(ctx->client_key_shares[i].key_exchange);
                        }
                    }
                    free(ctx->client_key_shares);
                }
                ctx->client_key_shares_count = ctx->client_extensions.key_share->count;
                    if(ctx->client_key_shares_count > 0) {
                        ctx->client_key_shares = (tls13_key_share_entry_t*)malloc(ctx->client_key_shares_count * sizeof(tls13_key_share_entry_t));
                        if(ctx->client_key_shares) {
                            for(uint32_t i = 0; i < ctx->client_key_shares_count; i++) {
                            ctx->client_key_shares[i].group = ctx->client_extensions.key_share->entries[i].group;
                            ctx->client_key_shares[i].key_exchange_len = ctx->client_extensions.key_share->entries[i].key_exchange_len;
                            if(ctx->client_key_shares[i].key_exchange_len > 0) {
                                ctx->client_key_shares[i].key_exchange = (uint8_t*)malloc(ctx->client_key_shares[i].key_exchange_len);
                                if(ctx->client_key_shares[i].key_exchange) {
                                    memcpy(ctx->client_key_shares[i].key_exchange,
                                           ctx->client_extensions.key_share->entries[i].key_exchange,
                                           ctx->client_key_shares[i].key_exchange_len);
                                }
                            } else {
                                ctx->client_key_shares[i].key_exchange = NULL;
                            }
                        }
                    }
                }
            }
        }
    }
    /* Append Client Hello to transcript for key derivation */
    tls13_append_handshake_message(ctx, record.data, record.length);
    
    if(record.data) free(record.data);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Server: send ServerHello and derive handshake traffic keys from the shared secret.
 * @param[in,out] ctx Server context after ClientHello has been processed.
 * @return `NOXTLS_RETURN_SUCCESS` on success; key generation, encoding, or send error otherwise.
 */
noxtls_return_t noxtls_tls13_send_server_hello(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    uint8_t *server_hello = ctx->handshake_workspace;
    if(server_hello == NULL) {
        server_hello = (uint8_t*)noxtls_malloc(512 + 256);
        if(server_hello == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    uint8_t *key_share_entry = (ctx->handshake_workspace != NULL) ? (ctx->handshake_workspace + 512) : (server_hello + 512);
    uint32_t key_share_entry_len = 256;
    uint32_t offset = 0;
    drbg_state_t drbg_state;
    static const uint16_t supported_groups[] = { TLS_NAMED_GROUP_X25519, TLS_NAMED_GROUP_SECP256R1 };
    noxtls_return_t rc;
    tls_ecdhe_context_t *ecdhe_ctx = NULL;
    uint16_t selected_group = 0;

    /* Select first client key share group we support */
    for(uint32_t i = 0; i < ctx->client_key_shares_count && selected_group == 0; i++) {
        for(uint32_t j = 0; j < sizeof(supported_groups) / sizeof(supported_groups[0]); j++) {
            if(ctx->client_key_shares[i].group == supported_groups[j]) {
                selected_group = supported_groups[j];
                break;
            }
        }
    }
    if(selected_group == 0) {
        if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, 512 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    if(ctx->ecdhe_ctx != NULL) {
        noxtls_tls_ecdhe_context_free((tls_ecdhe_context_t*)ctx->ecdhe_ctx);
        free(ctx->ecdhe_ctx);
        ctx->ecdhe_ctx = NULL;
    }
    ecdhe_ctx = (tls_ecdhe_context_t*)malloc(sizeof(tls_ecdhe_context_t));
    if(ecdhe_ctx == NULL) {
        if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, 512 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_tls_ecdhe_context_init(ecdhe_ctx, selected_group) != NOXTLS_RETURN_SUCCESS ||
       noxtls_tls_ecdhe_generate_ephemeral_key(ecdhe_ctx) != NOXTLS_RETURN_SUCCESS) {
        noxtls_tls_ecdhe_context_free(ecdhe_ctx);
        free(ecdhe_ctx);
        if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, 512 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    ctx->ecdhe_ctx = ecdhe_ctx;
    if(noxtls_tls13_key_share_encode(ecdhe_ctx, key_share_entry, &key_share_entry_len) != NOXTLS_RETURN_SUCCESS) {
        if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, 512 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    /* Generate server random */
    if(drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, 512 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    if(drbg_generate(&drbg_state, ctx->server_random, sizeof(ctx->server_random) * 8u, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, 512 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    /* Build Server Hello noxtls_message */
    server_hello[offset++] = TLS_HANDSHAKE_SERVER_HELLO;
    server_hello[offset++] = 0x00;
    server_hello[offset++] = 0x00;
    server_hello[offset++] = 0x00;
    server_hello[offset++] = (TLS_VERSION_1_3 >> 8) & 0xFF;
    server_hello[offset++] = TLS_VERSION_1_3 & 0xFF;
    memcpy(server_hello + offset, ctx->server_random, 32);
    offset += 32;
    server_hello[offset++] = 0x00;
    server_hello[offset++] = (ctx->cipher_suite >> 8) & 0xFF;
    server_hello[offset++] = ctx->cipher_suite & 0xFF;
    server_hello[offset++] = 0x00;
    /* Extensions: supported_versions (0x002b) + key_share (0x0033) */
    uint32_t ext_start = offset;
    offset += 2;  /* Total extensions length placeholder */
    /* supported_versions: 2 bytes 0x0304 */
    server_hello[offset++] = (TLS_EXTENSION_SUPPORTED_VERSIONS >> 8) & 0xFF;
    server_hello[offset++] = TLS_EXTENSION_SUPPORTED_VERSIONS & 0xFF;
    server_hello[offset++] = 0x00;
    server_hello[offset++] = 2;
    server_hello[offset++] = (TLS_VERSION_1_3 >> 8) & 0xFF;
    server_hello[offset++] = TLS_VERSION_1_3 & 0xFF;
    /* key_share */
    server_hello[offset++] = (TLS_EXTENSION_KEY_SHARE >> 8) & 0xFF;
    server_hello[offset++] = TLS_EXTENSION_KEY_SHARE & 0xFF;
    server_hello[offset++] = (key_share_entry_len >> 8) & 0xFF;
    server_hello[offset++] = key_share_entry_len & 0xFF;
    memcpy(server_hello + offset, key_share_entry, key_share_entry_len);
    offset += key_share_entry_len;
    uint16_t ext_total = (uint16_t)(offset - ext_start - 2);
    server_hello[ext_start] = (ext_total >> 8) & 0xFF;
    server_hello[ext_start + 1] = ext_total & 0xFF;
    uint32_t handshake_len = offset - 4;
    server_hello[1] = (handshake_len >> 16) & 0xFF;
    server_hello[2] = (handshake_len >> 8) & 0xFF;
    server_hello[3] = handshake_len & 0xFF;
    tls13_append_handshake_message(ctx, server_hello, offset);
    rc = noxtls_tls_send_record(&ctx->base, TLS_RECORD_HANDSHAKE, server_hello, offset);
    if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, 512 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = noxtls_tls13_process_client_key_share(ctx, ecdhe_ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    if(ecdhe_ctx->shared_secret == NULL || ecdhe_ctx->shared_secret_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = tls13_derive_handshake_keys(ctx, ecdhe_ctx->shared_secret, ecdhe_ctx->shared_secret_len);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    ctx->handshake_encrypted = 1;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Server: send EncryptedExtensions (ALPN, etc.) under handshake encryption.
 * @param[in,out] ctx Server context with handshake write keys installed.
 * @return `NOXTLS_RETURN_SUCCESS` on success; error from message build or encrypted send.
 */
noxtls_return_t noxtls_tls13_send_encrypted_extensions(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    uint8_t *encrypted_extensions = ctx->handshake_workspace;
    if(encrypted_extensions == NULL) {
        encrypted_extensions = (uint8_t*)noxtls_malloc(512);
        if(encrypted_extensions == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    uint32_t offset = 0;
    
    /* Build Encrypted Extensions noxtls_message */
    encrypted_extensions[offset++] = TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS;
    encrypted_extensions[offset++] = 0x00;  /* Length (3 bytes) - placeholder */
    encrypted_extensions[offset++] = 0x00;
    encrypted_extensions[offset++] = 0x00;
    
    /* Extensions length (2 bytes) - empty for minimal server */
    encrypted_extensions[offset++] = 0x00;
    encrypted_extensions[offset++] = 0x00;
    
    /* Update handshake noxtls_message length */
    uint32_t handshake_len = offset - 4;
    encrypted_extensions[1] = (handshake_len >> 16) & 0xFF;
    encrypted_extensions[2] = (handshake_len >> 8) & 0xFF;
    encrypted_extensions[3] = handshake_len & 0xFF;
    tls13_append_handshake_message(ctx, encrypted_extensions, offset);
    noxtls_return_t rc;
    if(ctx->handshake_encrypted) {
        rc = tls13_send_encrypted_handshake(ctx, encrypted_extensions, offset);
    } else {
        rc = noxtls_tls_send_record(&ctx->base, TLS_RECORD_HANDSHAKE, encrypted_extensions, offset);
    }
    if(encrypted_extensions != ctx->handshake_workspace) NOXTLS_SECURE_FREE(encrypted_extensions, 512); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return rc;
}

/**
 * @brief Server: send Certificate message from the configured server chain.
 * @param[in,out] ctx Server context with `server_cert` / chain configured.
 * @return `NOXTLS_RETURN_SUCCESS` on success; error if no certificate or send failure.
 */
noxtls_return_t noxtls_tls13_send_certificate(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.role != TLS_ROLE_SERVER) {
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
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if(ctx->server_cert == NULL || ctx->server_cert_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Build Certificate noxtls_message */
    certificate[offset++] = TLS_HANDSHAKE_CERTIFICATE;
    certificate[offset++] = 0x00;  /* Length (3 bytes) - placeholder */
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;
    
    /* Certificate request context (1 byte) - empty for server */
    certificate[offset++] = 0x00;
    
    if(ctx->server_cert_len > (uint32_t)(UINT32_MAX - 3u)) {
        if(certificate != ctx->handshake_workspace) NOXTLS_SECURE_FREE(certificate, TLS_HANDSHAKE_WORKSPACE_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    /* Certificate list length (3 bytes) */
    uint32_t cert_list_len = ctx->server_cert_len + 3;  /* +3 for certificate entry length field */
    certificate[offset++] = (cert_list_len >> 16) & 0xFF;
    certificate[offset++] = (cert_list_len >> 8) & 0xFF;
    certificate[offset++] = cert_list_len & 0xFF;
    
    /* Certificate entry length (3 bytes) */
    certificate[offset++] = (ctx->server_cert_len >> 16) & 0xFF;
    certificate[offset++] = (ctx->server_cert_len >> 8) & 0xFF;
    certificate[offset++] = ctx->server_cert_len & 0xFF;
    
    /* Certificate data + trailing extensions length (2 bytes) */
    if(offset > TLS_HANDSHAKE_WORKSPACE_SIZE ||
       (TLS_HANDSHAKE_WORKSPACE_SIZE - offset) < 2u ||
       ctx->server_cert_len > (TLS_HANDSHAKE_WORKSPACE_SIZE - offset - 2u)) {
        if(certificate != ctx->handshake_workspace) NOXTLS_SECURE_FREE(certificate, TLS_HANDSHAKE_WORKSPACE_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(certificate + offset, ctx->server_cert, ctx->server_cert_len);
    offset += ctx->server_cert_len;
    
    /* Extensions length (2 bytes) - no extensions */
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;
    
    /* Update handshake noxtls_message length */
    uint32_t handshake_len = offset - 4;
    certificate[1] = (handshake_len >> 16) & 0xFF;
    certificate[2] = (handshake_len >> 8) & 0xFF;
    certificate[3] = handshake_len & 0xFF;
    tls13_append_handshake_message(ctx, certificate, offset);
    noxtls_return_t rc;
    if(ctx->handshake_encrypted) {
        rc = tls13_send_encrypted_handshake(ctx, certificate, offset);
    } else {
        rc = noxtls_tls_send_record(&ctx->base, TLS_RECORD_HANDSHAKE, certificate, offset);
    }
    if(certificate != ctx->handshake_workspace) NOXTLS_SECURE_FREE(certificate, TLS_HANDSHAKE_WORKSPACE_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return rc;
}

/**
 * @brief Server: sign the handshake transcript and send CertificateVerify.
 * @param[in,out] ctx Server context with private key configured for the selected certificate.
 * @return `NOXTLS_RETURN_SUCCESS` on success; signing or send error otherwise.
 */
noxtls_return_t noxtls_tls13_send_certificate_verify(tls13_context_t *ctx)
{
    uint8_t certificate_verify[8 + 512];  /* header 8 + max RSA signature 512 */
    uint32_t offset = 0;
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    uint8_t transcript_hash[64];
    uint32_t transcript_len = sizeof(transcript_hash);
    static const char ctx_str[] = "TLS 1.3;
    static const char server CertificateVerify";
    uint8_t to_sign[64 + sizeof(ctx_str) + 1 + 64];
    uint32_t to_sign_len;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    if(ctx->server_private_rsa == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                             transcript_hash, &transcript_len);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    memset(to_sign, 0x20, 64);
    to_sign_len = 64;
    memcpy(to_sign + to_sign_len, ctx_str, sizeof(ctx_str));
    to_sign_len += sizeof(ctx_str);
    to_sign[to_sign_len++] = 0x00;
    memcpy(to_sign + to_sign_len, transcript_hash, transcript_len);
    to_sign_len += transcript_len;

    certificate_verify[offset++] = TLS_HANDSHAKE_CERTIFICATE_VERIFY;
    certificate_verify[offset++] = 0x00;
    certificate_verify[offset++] = 0x00;
    certificate_verify[offset++] = 0x00;
    /* Signature algorithm: rsa_pss_rsae_sha256 (0x0804) when using RSA */
    certificate_verify[offset++] = 0x08;
    certificate_verify[offset++] = 0x04;
    uint16_t signature_len = sizeof(certificate_verify) - 8;
    rc = noxtls_rsa_sign_pss((const rsa_key_t*)ctx->server_private_rsa, to_sign, to_sign_len,
                             certificate_verify + 8, &signature_len, NOXTLS_HASH_SHA_256);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    certificate_verify[offset++] = (signature_len >> 8) & 0xFF;
    certificate_verify[offset++] = signature_len & 0xFF;
    offset += signature_len;
    uint32_t handshake_len = offset - 4;
    certificate_verify[1] = (handshake_len >> 16) & 0xFF;
    certificate_verify[2] = (handshake_len >> 8) & 0xFF;
    certificate_verify[3] = handshake_len & 0xFF;
    tls13_append_handshake_message(ctx, certificate_verify, offset);
    if(ctx->handshake_encrypted) {
        return tls13_send_encrypted_handshake(ctx, certificate_verify, offset);
    }
    return noxtls_tls_send_record(&ctx->base, TLS_RECORD_HANDSHAKE, certificate_verify, offset);
}

/**
 * @brief Server: send Finished and derive application traffic secrets.
 * @param[in,out] ctx Server context after CertificateVerify has been sent.
 * @return `NOXTLS_RETURN_SUCCESS` on success; error from Finished build, send, or key derivation.
 */
noxtls_return_t noxtls_tls13_send_finished_server(tls13_context_t *ctx)
{
    uint8_t finished[64];
    uint32_t offset = 0;
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    uint8_t transcript_hash[64];
    uint32_t transcript_len = sizeof(transcript_hash);
    uint8_t finished_key[64];
    uint32_t verify_len;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                             transcript_hash, &transcript_len);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->server_handshake_traffic_secret, hash_len,
                                 (const uint8_t*)"finished", 8, NULL, 0,
                                 finished_key, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    verify_len = hash_len;
    rc = hmac_compute(hash_algo, finished_key, hash_len, transcript_hash, transcript_len,
                     finished + 4, &verify_len);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    finished[0] = TLS_HANDSHAKE_FINISHED;
    finished[1] = 0x00;
    finished[2] = 0x00;
    finished[3] = (uint8_t)verify_len;
    offset = 4 + verify_len;
    /* RFC 5929: store first Finished verify_data for tls-unique (TLS 1.3 server sends first) */
    if(ctx->channel_binding_first_finished_len == 0 && verify_len <= sizeof(ctx->channel_binding_first_finished)) {
        memcpy(ctx->channel_binding_first_finished, finished + 4, verify_len);
        ctx->channel_binding_first_finished_len = verify_len;
    }
    tls13_append_handshake_message(ctx, finished, offset);
    if(ctx->handshake_encrypted) {
        return tls13_send_encrypted_handshake(ctx, finished, offset);
    }
    return noxtls_tls_send_record(&ctx->base, TLS_RECORD_HANDSHAKE, finished, offset);
}

/**
 * @brief Server: receive client Finished, verify, and install application traffic keys.
 * @param[in,out] ctx Server context after server Finished has been sent.
 * @return `NOXTLS_RETURN_SUCCESS` when application keys are installed; verify or I/O error otherwise.
 */
noxtls_return_t noxtls_tls13_recv_finished_client(tls13_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    rc = noxtls_tls_recv_record(&ctx->base, &record);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(record.length > 0 && record.data == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if(record.type != TLS_RECORD_HANDSHAKE || record.length != 36) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    if(record.data[0] != TLS_HANDSHAKE_FINISHED) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    uint8_t transcript_hash[64];
    uint32_t transcript_len = sizeof(transcript_hash);
    uint8_t finished_key[64];
    uint8_t verify_data[64];
    uint32_t verify_len;
    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        if(record.data) free(record.data);
        return rc;
    }
    rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                             transcript_hash, &transcript_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        if(record.data) free(record.data);
        return rc;
    }
    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->client_handshake_traffic_secret, hash_len,
                                 (const uint8_t*)"finished", 8, NULL, 0,
                                 finished_key, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        if(record.data) free(record.data);
        return rc;
    }
    verify_len = hash_len;
    rc = hmac_compute(hash_algo, finished_key, hash_len, transcript_hash, transcript_len,
                     verify_data, &verify_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        if(record.data) free(record.data);
        return rc;
    }
    if(record.length < 4u + verify_len || noxtls_secret_memcmp(record.data + 4, verify_data, verify_len) != 0) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    if(record.data) free(record.data);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Server: run the full TLS 1.3 handshake through application key installation.
 * @param[in,out] ctx Initialized server context with credentials configured.
 * @return `NOXTLS_RETURN_SUCCESS` when the handshake completes; error from any server step.
 */
noxtls_return_t noxtls_tls13_accept(tls13_context_t *ctx)
{
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    ctx->base.state = TLS_STATE_HANDSHAKING;
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_START);
    
    /* Receive Client Hello */
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_RECV_CH);
    rc = noxtls_tls13_recv_client_hello(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_CH, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_CH, rc);
    
    /* Send Server Hello (includes key share, derives handshake keys, enables handshake encryption) */
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_SEND_SH);
    rc = noxtls_tls13_send_server_hello(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_SH, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_SH, rc);
    
    /* Send Encrypted Extensions */
    rc = noxtls_tls13_send_encrypted_extensions(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    /* Send Certificate */
    rc = noxtls_tls13_send_certificate(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    /* Send Certificate Verify */
    rc = noxtls_tls13_send_certificate_verify(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    /* Send Finished */
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED);
    rc = noxtls_tls13_send_finished_server(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED, rc);
    
    /* Receive Finished */
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED);
    rc = noxtls_tls13_recv_finished_client(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED, rc);
    
    rc = tls13_derive_application_secrets(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls13_install_application_keys(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    ctx->base.state = TLS_STATE_CONNECTED;
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_CONNECTED);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Send application data on an established TLS 1.3 or DTLS 1.3 connection.
 * @param[in,out] ctx  Context with application write keys installed.
 * @param[in] data     Plaintext application bytes.
 * @param[in] len      Length of @p data.
 * @return `NOXTLS_RETURN_SUCCESS` on success; encrypt or transport error otherwise.
 */
noxtls_return_t noxtls_tls13_send(tls13_context_t *ctx, const uint8_t *data, uint32_t len)
{
    uint32_t inner_len = TLS13_IMPL_RECORD_WORKSPACE_HALF;
    uint32_t encrypted_len = TLS13_IMPL_RECORD_WORKSPACE_HALF;  /* Extra space for tag */
    uint8_t *inner = ctx->record_workspace;
    uint8_t *encrypted_record = ctx->record_workspace + TLS13_IMPL_RECORD_WORKSPACE_HALF;
    noxtls_return_t rc;
    
    if(ctx == NULL || data == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.state != TLS_STATE_CONNECTED) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if(len > TLS_MAX_RECORD_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    
    if(ctx->record_workspace == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    
    /* Build TLSInnerPlaintext with application data content type */
    rc = tls13_build_inner_plaintext(data, len, TLS_RECORD_APPLICATION_DATA, inner, &inner_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(tls13_is_dtls(ctx)) {
        return noxtls_tls13_send_dtls13_encrypted_record(ctx, 0, TLS_RECORD_APPLICATION_DATA, inner, inner_len, 1);
    }

    /* Encrypt application data using AEAD */
    rc = noxtls_tls13_encrypt_record(ctx, TLS_RECORD_APPLICATION_DATA, inner, inner_len,
                              encrypted_record, &encrypted_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return noxtls_tls_send_record(&ctx->base, TLS_RECORD_APPLICATION_DATA, encrypted_record, encrypted_len);
}

/**
 * @brief Receive application data on an established TLS 1.3 or DTLS 1.3 connection.
 * @param[in,out] ctx  Context with application read keys installed.
 * @param[out] data    Buffer for decrypted application plaintext.
 * @param[in,out] len  On input, size of @p data; on success, bytes written.
 * @return `NOXTLS_RETURN_SUCCESS` on success; I/O, decrypt, or inner-plaintext error otherwise.
 */
noxtls_return_t noxtls_tls13_recv(tls13_context_t *ctx, uint8_t *data, uint32_t *len)
{
    tls_record_t record;
    noxtls_return_t rc;
    uint8_t content_type = 0;
    
    if(ctx == NULL || data == NULL || len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.state != TLS_STATE_CONNECTED) {
        return NOXTLS_RETURN_FAILED;
    }
    
    rc = noxtls_tls_recv_record(&ctx->base, &record);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(record.length > 0 && record.data == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if(record.type != TLS_RECORD_APPLICATION_DATA) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Decrypt application data using AEAD */
    rc = noxtls_tls13_decrypt_record(ctx, record.data, record.length, data, len);
    if(record.data) free(record.data);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_CRYPTO, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_DECRYPT_FAIL, rc, record.length);
        return rc;
    }

    rc = tls13_extract_inner_plaintext(data, len, &content_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(content_type != TLS_RECORD_APPLICATION_DATA) {
        return NOXTLS_RETURN_FAILED;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Send close_notify and mark the connection closed (TLS 1.3 / DTLS 1.3).
 * @param[in,out] ctx Established context.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p ctx is NULL; send error otherwise.
 */
noxtls_return_t noxtls_tls13_close(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Send close_notify alert */
    tls_send_alert(&ctx->base, TLS_ALERT_LEVEL_WARNING, TLS_ALERT_CLOSE_NOTIFY);
    
    ctx->base.state = TLS_STATE_CLOSED;
    
    return NOXTLS_RETURN_SUCCESS;
}

