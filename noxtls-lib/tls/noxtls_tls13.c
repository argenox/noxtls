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
* File:    noxtls_tls13.c
* Summary: TLS 1.3 Implementation
*
*****************************************************************************/

// cppcheck-suppress-file unusedFunction
// cppcheck-suppress-file variableScope
// cppcheck-suppress-file constParameterPointer

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum
{
    TLS13_CLIENT_HS_STEP_NONE = 0,
    TLS13_CLIENT_HS_STEP_SEND_CH,
    TLS13_CLIENT_HS_STEP_RECV_SH,
    TLS13_CLIENT_HS_STEP_RECV_ENC_EXT,
    TLS13_CLIENT_HS_STEP_RECV_CERT_REQ,
    TLS13_CLIENT_HS_STEP_RECV_CERT,
    TLS13_CLIENT_HS_STEP_RECV_CERT_VERIFY,
    TLS13_CLIENT_HS_STEP_RECV_FINISHED,
    TLS13_CLIENT_HS_STEP_DERIVE_APP_SECRETS,
    TLS13_CLIENT_HS_STEP_SEND_CLIENT_AUTH,
    TLS13_CLIENT_HS_STEP_SEND_EOED,
    TLS13_CLIENT_HS_STEP_SEND_FINISHED,
    TLS13_CLIENT_HS_STEP_INSTALL_APP_KEYS
} tls13_client_handshake_step_t;

typedef enum
{
    TLS13_SERVER_HS_STEP_NONE = 0,
    TLS13_SERVER_HS_STEP_RECV_CH,
    TLS13_SERVER_HS_STEP_PICK_SERVER_IDENTITY,
    TLS13_SERVER_HS_STEP_SELECT_CERT_SIG_SCHEME,
    TLS13_SERVER_HS_STEP_SNI_CHECK,
    TLS13_SERVER_HS_STEP_SEND_SH,
    TLS13_SERVER_HS_STEP_SEND_MIDDLEBOX_CCS,
    TLS13_SERVER_HS_STEP_PROCESS_CLIENT_SHARE,
    TLS13_SERVER_HS_STEP_SEND_ENCRYPTED_EXTENSIONS,
    TLS13_SERVER_HS_STEP_SEND_CERTIFICATE_REQUEST,
    TLS13_SERVER_HS_STEP_SEND_CERTIFICATE,
    TLS13_SERVER_HS_STEP_SEND_CERTIFICATE_VERIFY,
    TLS13_SERVER_HS_STEP_SEND_FINISHED,
    TLS13_SERVER_HS_STEP_DERIVE_APP_SECRETS,
    TLS13_SERVER_HS_STEP_INSTALL_SERVER_APP_WRITE_KEYS,
    TLS13_SERVER_HS_STEP_RECV_CLIENT_CERTIFICATE,
    TLS13_SERVER_HS_STEP_RECV_CLIENT_CERTIFICATE_VERIFY,
    TLS13_SERVER_HS_STEP_RECV_FINISHED,
    TLS13_SERVER_HS_STEP_FLUSH_ACK,
    TLS13_SERVER_HS_STEP_INSTALL_CLIENT_APP_READ_KEYS,
    TLS13_SERVER_HS_STEP_SEND_NEW_SESSION_TICKET
} tls13_server_handshake_step_t;
#include <limits.h>
#include <time.h>
#if defined(__has_include)
#if defined(ESP_PLATFORM) && __has_include("esp_timer.h")
#include "esp_timer.h"
#endif
#endif
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "common/noxtls_debug_printf.h"
#include "common/noxtls_ct.h"
#include "noxtls_tls13.h"
#include "noxtls_tls13_psk.h"
#include "drbg/noxtls_drbg.h"
#include "certs/noxtls_x509.h"
#include "noxtls_tls_kdf.h"
#include "mac/noxtls_hmac.h"
#include "kdf/noxtls_hkdf.h"
#include "noxtls_tls_key_exchange.h"
#include "noxtls_tls_common.h"
#include "noxtls_tls_noxsight.h"
#include "pkc/rsa/noxtls_rsa.h"
#include "pkc/ecdsa/noxtls_ecdsa.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "pkc/dh/noxtls_dh.h"
#include "pkc/x25519/noxtls_x25519.h"
#include "pkc/x448/noxtls_x448.h"
#include "pkc/ed25519/noxtls_ed25519.h"
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
#include "pkc/ed448/noxtls_ed448.h"
#endif
#if NOXTLS_FEATURE_ML_KEM
#include "pkc/mlkem/noxtls_mlkem.h"
#endif
#if NOXTLS_FEATURE_ML_DSA
#include "pkc/mldsa/noxtls_mldsa.h"
#endif
#if NOXTLS_FEATURE_SLH_DSA
#include "pkc/slhdsa/noxtls_slhdsa.h"
#endif
#if NOXTLS_FEATURE_FALCON
#include "pkc/falcon/noxtls_falcon.h"
#endif
#include "mdigest/noxtls_hash.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"

#define TLS13_DTLS_HRR_COOKIE_MAX_LEN (TLS_CLIENT_HELLO_DEFAULT_SIZE - 512U)

static noxtls_return_t tls13_dtls_store_hrr_cookie(tls13_context_t *ctx, const uint8_t *cookie, uint16_t cookie_len)
{
    uint8_t *copy;

    if(ctx == NULL || cookie == NULL || cookie_len == 0U) {
        return NOXTLS_RETURN_NULL;
    }
    if((uint32_t)cookie_len > TLS13_DTLS_HRR_COOKIE_MAX_LEN) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    copy = (uint8_t*)noxtls_malloc(cookie_len);
    if(copy == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    memcpy(copy, cookie, cookie_len);

    if(ctx->base.hrr_cookie != NULL) {
        noxtls_free(ctx->base.hrr_cookie);
    }
    ctx->base.hrr_cookie = copy;
    ctx->base.hrr_cookie_len = cookie_len;
    return NOXTLS_RETURN_SUCCESS;
}

static char s_tls13_last_accept_fail_step[48];
static char s_tls13_last_connect_fail_step[48];
static char tls13_keylog_path[512] = {0};

/* Forward declarations for local helpers used before definition */
static noxtls_return_t tls13_hash_messages(noxtls_hash_algos_t hash_algo,
                                           const uint8_t *messages,
                                           uint32_t messages_len,
                                           uint8_t *out_hash,
                                           uint32_t *out_hash_len);
static noxtls_return_t tls13_get_cipher_params(uint16_t cipher_suite,
                                                noxtls_hash_algos_t *hash_algo,
                                                uint32_t *hash_len,
                                                uint32_t *key_len);
static noxtls_return_t tls13_send_encrypted_handshake(tls13_context_t *ctx,
                                                      const uint8_t *msg,
                                                      uint32_t msg_len);
static void tls13_connect_log_fail(const tls13_context_t *ctx, const char *step, noxtls_return_t rc);
static void tls13_accept_log_fail(const tls13_context_t *ctx, const char *step, noxtls_return_t rc);
static noxtls_return_t tls13_context_init_internal(tls13_context_t *ctx,
                                                   tls_role_t role,
                                                   uint8_t *record_workspace,
                                                   uint32_t record_workspace_len,
                                                   uint8_t *handshake_workspace,
                                                   uint32_t handshake_workspace_len);
static noxtls_return_t tls13_derive_handshake_keys(tls13_context_t *ctx,
                                                   const uint8_t *shared_secret,
                                                   uint32_t shared_secret_len);
static int tls13_is_dtls(const tls13_context_t *ctx);
static int tls13_group_is_ffdhe(uint16_t group);

static noxtls_return_t tls13_send_middlebox_compat_ccs(tls13_context_t *ctx);
static void tls13_try_store_nst_from_handshake(tls13_context_t *ctx, const uint8_t *decrypted, uint32_t decrypted_len);
static int tls13_client_supports_signature_scheme(const tls13_context_t *ctx, uint16_t sig_scheme);
static void tls13_send_handshake_alert_for_error(tls13_context_t *ctx, noxtls_return_t rc);
static int tls13_ecdsa_scheme_matches_curve(ecc_curve_t curve_kind, uint16_t scheme);
#if !NOXTLS_CFG_TLS13_ALLOW_RSA_PKCS1_CERTVERIFY
static int tls13_sig_scheme_is_deprecated_rsa_pkcs1_tls13(uint16_t scheme);
#endif
static int tls13_server_can_sign_scheme(const tls13_context_t *ctx, uint16_t scheme);
static uint16_t tls13_select_server_certificate_sig_scheme_legacy(const tls13_context_t *ctx);
static void tls13_pick_server_ecdsa_identity_from_matrix(tls13_context_t *ctx);
static int tls13_ecdsa_sig_scheme_to_hash(uint16_t scheme, noxtls_hash_algos_t *out_hash);
#if NOXTLS_FEATURE_SLH_DSA
static uint16_t tls13_slhdsa_param_to_sig_scheme(noxtls_slhdsa_param_t param);
static noxtls_return_t tls13_slhdsa_sig_scheme_to_param(uint16_t scheme, noxtls_slhdsa_param_t *param);
#endif
static noxtls_return_t tls13_build_inner_plaintext(const uint8_t *content, uint32_t content_len,
                                                   uint8_t content_type, uint8_t *out_plaintext,
                                                   uint32_t *out_len);
void tls13_release_handshake_cert_buffer(tls13_context_t *ctx, uint8_t *certificate);
static void tls13_free_client_key_shares(tls13_context_t *ctx);
static void tls13_free_server_key_share(tls13_context_t *ctx);
static void tls13_release_ecdhe_ctx(tls13_context_t *ctx);
static void tls13_connect_log_fail_detail(const tls13_context_t *ctx,
                                          const char *prefix,
                                          const char *detail,
                                          noxtls_return_t rc);
static void tls13_accept_log_fail_detail(const tls13_context_t *ctx,
                                         const char *prefix,
                                         const char *detail,
                                         noxtls_return_t rc);







/**
 * @brief Get the current time in microseconds
 *
 * @return The current time in microseconds
 */
static uint64_t tls13_profile_now_us(void)
{
#if defined(__has_include) && defined(ESP_PLATFORM) && __has_include("esp_timer.h")
    return (uint64_t)esp_timer_get_time();
#else
    clock_t now = clock();

    if(now <= (clock_t)0) {
        return 0U;
    }
    return ((uint64_t)now * 1000000u) / (uint64_t)CLOCKS_PER_SEC;
#endif
}

/**
 * @brief Get the elapsed time in microseconds
 *
 * @param[in] start_us The start time in microseconds
 * @return The elapsed time in microseconds
 */
static uint64_t tls13_profile_elapsed_us(uint64_t start_us)
{
    uint64_t now_us = tls13_profile_now_us();

    if(now_us < start_us) {
        return 0U;
    }
    return now_us - start_us;
}

static void tls13_connect_log_fail_detail(const tls13_context_t *ctx,
                                          const char *prefix,
                                          const char *detail,
                                          noxtls_return_t rc)
{
    char step[48];
    int written;

    if(detail == NULL || detail[0] == '\0') {
        tls13_connect_log_fail(ctx, prefix, rc);
        return;
    }

    written = snprintf(step, sizeof(step), "%s/%s", prefix, detail);
    if(written < 0 || (size_t)written >= sizeof(step)) {
        tls13_connect_log_fail(ctx, prefix, rc);
        return;
    }

    tls13_connect_log_fail(ctx, step, rc);
}

/**
 * @brief Check if a named group is a ML-KEM group
 *
 * @param[in] group The named group to check
 * @return 1 if the group is a ML-KEM group, 0 otherwise
 */
static int tls13_group_is_mlkem(uint16_t group)
{
    return group == TLS_NAMED_GROUP_MLKEM512 ||
           group == TLS_NAMED_GROUP_MLKEM768 ||
           group == TLS_NAMED_GROUP_MLKEM1024;
}

/**
 * @brief Check if a named group is a hybrid group
 *
 * @param[in] group The named group to check
 * @return 1 if the group is a hybrid group, 0 otherwise
 */
static int tls13_group_is_hybrid(uint16_t group)
{
    return group == TLS_NAMED_GROUP_X25519_MLKEM512 ||
           group == TLS_NAMED_GROUP_X25519_MLKEM768 ||
           group == TLS_NAMED_GROUP_X25519_MLKEM768_LEGACY ||
           group == TLS_NAMED_GROUP_X25519_MLKEM1024;
}

/**
 * @brief Check if a named group is supported by the server
 *
 * @param[in] group The named group to check
 * @return 1 if the group is supported by the server, 0 otherwise
 */
static int tls13_server_supports_group(uint16_t group)
{
#if NOXTLS_FEATURE_ML_KEM
    if(tls13_group_is_mlkem(group) || tls13_group_is_hybrid(group)) {
        return 1;
    }
#endif
    return group == TLS_NAMED_GROUP_X25519 ||
           group == TLS_NAMED_GROUP_X448 ||
           group == TLS_NAMED_GROUP_SECP256R1 ||
           group == TLS_NAMED_GROUP_SECP384R1 ||
           group == TLS_NAMED_GROUP_SECP521R1 ||
           tls13_group_is_ffdhe(group);
}

/**
 * @brief Get the ML-KEM parameter for a named group
 *
 * @param[in] group The named group to get the ML-KEM parameter for
 * @return The ML-KEM parameter
 */
static noxtls_mlkem_param_t tls13_group_mlkem_param(uint16_t group)
{
    switch(group) {
        case TLS_NAMED_GROUP_MLKEM512:
        case TLS_NAMED_GROUP_X25519_MLKEM512:
            return NOXTLS_MLKEM_512;
        case TLS_NAMED_GROUP_MLKEM768:
        case TLS_NAMED_GROUP_X25519_MLKEM768:
        case TLS_NAMED_GROUP_X25519_MLKEM768_LEGACY:
            return NOXTLS_MLKEM_768;
        case TLS_NAMED_GROUP_MLKEM1024:
        case TLS_NAMED_GROUP_X25519_MLKEM1024:
            return NOXTLS_MLKEM_1024;
        default:
            return NOXTLS_MLKEM_NONE;
    }
}

/**
 * @brief Build the supported groups list
 *
 * @param[in] groups The groups to build the supported groups list from
 * @param[in] max_groups The maximum number of groups to build the supported groups list from
 * @return The number of groups in the supported groups list
 */
static uint32_t tls13_build_supported_groups(uint16_t *groups, uint32_t max_groups)
{
    uint32_t count = 0;
    if(groups == NULL || max_groups == 0) {
        return 0;
    }

#if NOXTLS_CFG_TLS13_PREFER_SECP256R1_OVER_X25519
    groups[count++] = TLS_NAMED_GROUP_SECP256R1;
    if(count < max_groups) groups[count++] = TLS_NAMED_GROUP_X25519;
#else
    groups[count++] = TLS_NAMED_GROUP_X25519;
    if(count < max_groups) groups[count++] = TLS_NAMED_GROUP_SECP256R1;
#endif
    if(count < max_groups) groups[count++] = TLS_NAMED_GROUP_SECP384R1;
#if NOXTLS_FEATURE_ML_KEM
    if(count < max_groups) groups[count++] = TLS_NAMED_GROUP_MLKEM512;
    if(count < max_groups) groups[count++] = TLS_NAMED_GROUP_MLKEM768;
    if(count < max_groups) groups[count++] = TLS_NAMED_GROUP_MLKEM1024;
    if(count < max_groups) groups[count++] = TLS_NAMED_GROUP_X25519_MLKEM512;
    if(count < max_groups) groups[count++] = TLS_NAMED_GROUP_X25519_MLKEM768;
    if(count < max_groups) groups[count++] = TLS_NAMED_GROUP_X25519_MLKEM1024;
#endif
    return count;
}

/**
 * @brief Build the signature algorithms list
 *
 * @param[in] algorithms The algorithms to build the signature algorithms list from
 * @param[in] max_algorithms The maximum number of algorithms to build the signature algorithms list from
 * @return The number of algorithms in the signature algorithms list
 */
static uint32_t tls13_build_signature_algorithms(uint16_t *algorithms, uint32_t max_algorithms)
{
    uint32_t count = 0;
    if(algorithms == NULL || max_algorithms == 0) {
        return 0;
    }
    algorithms[count++] = TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256;
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256;
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_ED25519;
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_ED448;
#endif
    if(count < max_algorithms) algorithms[count++] = 0x0401; /* rsa_pkcs1_sha256 */
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384;
    if(count < max_algorithms) algorithms[count++] = 0x0805; /* rsa_pss_rsae_sha384 */
#if NOXTLS_FEATURE_ML_DSA
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_MLDSA44;
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_MLDSA65;
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_MLDSA87;
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_RSA_PSS_SHA256_MLDSA44;
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_RSA_PSS_SHA256_MLDSA65;
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_RSA_PSS_SHA384_MLDSA87;
#endif
#if NOXTLS_FEATURE_SLH_DSA
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_SLHDSA_SHA2_128S;
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_SLHDSA_SHA2_128F;
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_SLHDSA_SHA2_192S;
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_SLHDSA_SHA2_192F;
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_SLHDSA_SHA2_256S;
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_SLHDSA_SHA2_256F;
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_SLHDSA_SHAKE_128S;
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_SLHDSA_SHAKE_128F;
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_SLHDSA_SHAKE_192S;
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_SLHDSA_SHAKE_192F;
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_SLHDSA_SHAKE_256S;
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_SLHDSA_SHAKE_256F;
#endif
#if NOXTLS_FEATURE_FALCON
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_FALCON512;
    if(count < max_algorithms) algorithms[count++] = TLS_SIGSCHEME_FALCON1024;
#endif
    return count;
}

#if NOXTLS_FEATURE_ML_KEM

/**
 * @brief Combine the classical and PQ secrets
 *
 * @param[in] ctx The context to combine the classical and PQ secrets from
 * @param[in] classical_secret The classical secret
 * @param[in] classical_secret_len The length of the classical secret
 * @param[in] pq_secret The PQ secret
 * @param[in] pq_secret_len The length of the PQ secret
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, or NOXTLS_RETURN_INVALID_PARAM 
 *         if the classical or PQ secret is invalid or the combination fails
 */
static noxtls_return_t tls13_combine_hybrid_secrets(tls13_context_t *ctx,
                                                    const uint8_t *classical_secret,
                                                    uint32_t classical_secret_len,
                                                    const uint8_t *pq_secret,
                                                    uint32_t pq_secret_len)
{
    noxtls_sha_ctx_t sha_ctx;
    uint8_t digest[32];
    noxtls_return_t rc;

    if(ctx == NULL || classical_secret == NULL || pq_secret == NULL ||
       classical_secret_len == 0 || pq_secret_len == 0) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_sha256_init(&sha_ctx, NOXTLS_HASH_SHA_256);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_sha256_update(&sha_ctx, (uint8_t *)classical_secret, classical_secret_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_sha256_update(&sha_ctx, (uint8_t *)pq_secret, pq_secret_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_sha256_finish(&sha_ctx, digest);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    memcpy(ctx->hybrid_shared_secret, digest, sizeof(digest));
    ctx->hybrid_shared_secret_len = (uint32_t)sizeof(digest);
    return NOXTLS_RETURN_SUCCESS;
}
#endif /* NOXTLS_FEATURE_ML_KEM */

/**
 * @brief Check if the client supports a named group
 *
 * @param[in] ctx The context to check if the client supports the named group from
 * @param[in] group The named group to check if the client supports
 * @return 1 if the client supports the named group, 0 otherwise
 */
static int tls13_client_supports_group(const tls13_context_t *ctx, uint16_t group)
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

/**
 * @brief Check if the client has a key share for a named group
 *
 * @param[in] ctx The context to check if the client has a key share for the named group from
 * @param[in] group The named group to check if the client has a key share for
 * @return 1 if the client has a key share for the named group, 0 otherwise
 */
static int tls13_client_has_key_share_for_group(const tls13_context_t *ctx, uint16_t group)
{
    uint32_t i;
    if(ctx == NULL || ctx->client_key_shares == NULL) {
        return 0;
    }
    for(i = 0; i < ctx->client_key_shares_count; i++) {
        if(ctx->client_key_shares[i].group == group) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Check if a named group is a FFDHE group
 *
 * @param[in] group The named group to check
 * @return 1 if the group is a FFDHE group, 0 otherwise
 */
static int tls13_group_is_ffdhe(uint16_t group)
{
    return group == TLS_NAMED_GROUP_FFDHE2048 ||
           group == TLS_NAMED_GROUP_FFDHE3072 ||
           group == TLS_NAMED_GROUP_FFDHE4096 ||
           group == TLS_NAMED_GROUP_FFDHE6144 ||
           group == TLS_NAMED_GROUP_FFDHE8192;
}

/**
 * RFC 8446 appendix B.3.1.4 reserved/obsolete NamedGroup codepoints for TLS 1.3.
 * Matches tlsfuzzer test_tls13_obsolete_curves.py (client MUST NOT advertise these).
 */
/**
 * @brief Check if a named group is obsolete for TLS 1.3
 *
 * @param[in] group The named group to check
 * @return 1 if the group is obsolete, 0 otherwise
 */
static int tls13_named_group_obsolete_tls13(uint16_t group)
{
    if(group >= 0x0001u && group <= 0x0016u) {
        return 1;
    }
    if(group >= 0x001Au && group <= 0x001Cu) {
        return 1;
    }
    if(group == 0xFF01u || group == 0xFF02u) {
        return 1;
    }
    return 0;
}

/**
 * @brief Reject obsolete client named groups
 *
 * @param[in] ctx The context to reject the obsolete client named groups from
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, or NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER if the client named groups are obsolete
 */
static noxtls_return_t tls13_reject_obsolete_client_named_groups(const tls13_context_t *ctx)
{
    uint32_t i;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->client_extensions.supported_groups != NULL &&
       ctx->client_extensions.supported_groups->groups != NULL) {
        for(i = 0; i < ctx->client_extensions.supported_groups->count; i++) {
            if(tls13_named_group_obsolete_tls13(ctx->client_extensions.supported_groups->groups[i])) {
                return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
            }
        }
    }
    if(ctx->client_extensions.key_share != NULL) {
        for(i = 0; i < ctx->client_extensions.key_share->count; i++) {
            if(tls13_named_group_obsolete_tls13(ctx->client_extensions.key_share->entries[i].group)) {
                return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
            }
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * RFC 8446 key_share: reject duplicate NamedGroup entries and shares for groups
 * not listed in supported_groups (tlsfuzzer test_tls13_ffdhe_groups).
 */
/**
 * @brief Validate the client key share list
 *
 * @param[in] ctx The context to validate the client key share list from
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, or NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER if the client key share list is invalid
 */
static noxtls_return_t tls13_validate_client_key_share_list(const tls13_context_t *ctx)
{
    const tls_key_share_list_extension_t *ks;
    uint32_t i;
    uint32_t j;

    if(ctx == NULL || ctx->client_extensions.key_share == NULL) {
        return NOXTLS_RETURN_SUCCESS;
    }
    ks = ctx->client_extensions.key_share;
    for(i = 0; i < ks->count; i++) {
        for(j = i + 1U; j < ks->count; j++) {
            if(ks->entries[i].group == ks->entries[j].group) {
                return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
            }
        }
    }
    if(ctx->client_extensions.supported_groups != NULL &&
       ctx->client_extensions.supported_groups->groups != NULL) {
        for(i = 0; i < ks->count; i++) {
            uint16_t g = ks->entries[i].group;
            int found = 0;
            for(j = 0; j < ctx->client_extensions.supported_groups->count; j++) {
                if(ctx->client_extensions.supported_groups->groups[j] == g) {
                    found = 1;
                    break;
                }
            }
            if(found == 0) {
                return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
            }
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Validate the client key share
 *
 * @param[in] entry The client key share to validate
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the entry is NULL, or NOXTLS_RETURN_INVALID_PARAM if the client key share is invalid
 */
static noxtls_return_t tls13_validate_client_key_share(const tls_key_share_extension_t *entry)
{
    static const uint8_t x25519_all_zero[NOXTLS_X25519_KEY_SIZE] = { 0 };
    static const uint8_t x25519_one[NOXTLS_X25519_KEY_SIZE] = { 1 };
    static const uint8_t x448_all_zero[NOXTLS_X448_KEY_SIZE] = { 0 };
    static const uint8_t x448_one[NOXTLS_X448_KEY_SIZE] = { 1 };
    ecc_curve_t curve_type;
    ecc_point_t point;
    ecc_key_t curve_key;
    noxtls_return_t rc;
    uint32_t j;
    int all_zero_x = 1;
    int all_zero_y = 1;

    if(entry == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(entry->group == TLS_NAMED_GROUP_X25519) {
        if(entry->key_exchange_len != NOXTLS_X25519_KEY_SIZE || entry->key_exchange == NULL) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        if(noxtls_secret_memcmp(entry->key_exchange, x25519_all_zero, NOXTLS_X25519_KEY_SIZE) == 0 ||
           noxtls_secret_memcmp(entry->key_exchange, x25519_one, NOXTLS_X25519_KEY_SIZE) == 0) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
    } else if(entry->group == TLS_NAMED_GROUP_X448) {
        if(entry->key_exchange_len != NOXTLS_X448_KEY_SIZE || entry->key_exchange == NULL) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        if(noxtls_secret_memcmp(entry->key_exchange, x448_all_zero, NOXTLS_X448_KEY_SIZE) == 0 ||
           noxtls_secret_memcmp(entry->key_exchange, x448_one, NOXTLS_X448_KEY_SIZE) == 0) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
    } else if(entry->group == TLS_NAMED_GROUP_SECP256R1 ||
              entry->group == TLS_NAMED_GROUP_SECP384R1 ||
              entry->group == TLS_NAMED_GROUP_SECP521R1) {
        if(entry->key_exchange == NULL) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        rc = noxtls_tls_named_group_to_ecc_curve(entry->group, &curve_type);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        rc = noxtls_tls_decode_ecc_point_uncompressed(entry->key_exchange, entry->key_exchange_len, &point, curve_type);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        for(j = 0; j < point.size; j++) {
            if(point.x[j] != 0U) {
                all_zero_x = 0;
            }
            if(point.y[j] != 0U) {
                all_zero_y = 0;
            }
        }
        if(all_zero_x != 0 && all_zero_y != 0) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        rc = noxtls_ecc_key_init(&curve_key, curve_type);
        if(rc != NOXTLS_RETURN_SUCCESS || curve_key.curve == NULL) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        rc = noxtls_ecc_point_is_on_curve(&point, curve_key.curve);
        noxtls_ecc_key_free(&curve_key);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
    } else if(tls13_group_is_ffdhe(entry->group)) {
        rc = noxtls_dh_ffdhe_validate_client_key_share(entry->group, entry->key_exchange, entry->key_exchange_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Select the server group
 *
 * @param[in] ctx The context to select the server group from
 * @return The selected server group
 */
static uint16_t tls13_select_server_group(const tls13_context_t *ctx)
{
    static const uint16_t preferred_groups[] = {
#if NOXTLS_FEATURE_ML_KEM
        TLS_NAMED_GROUP_X25519_MLKEM768,
        TLS_NAMED_GROUP_X25519_MLKEM768_LEGACY,
        TLS_NAMED_GROUP_MLKEM768,
        TLS_NAMED_GROUP_X25519_MLKEM512,
        TLS_NAMED_GROUP_MLKEM512,
        TLS_NAMED_GROUP_X25519_MLKEM1024,
        TLS_NAMED_GROUP_MLKEM1024,
#endif
#if NOXTLS_CFG_TLS13_PREFER_SECP256R1_OVER_X25519
        TLS_NAMED_GROUP_SECP256R1,
        TLS_NAMED_GROUP_X25519,
#else
        TLS_NAMED_GROUP_X25519,
        TLS_NAMED_GROUP_SECP256R1,
#endif
        TLS_NAMED_GROUP_X448,
        TLS_NAMED_GROUP_SECP384R1,
        TLS_NAMED_GROUP_SECP521R1,
        /* Prefer smaller FFDHE groups first when the client offers several (cost + interop). */
        TLS_NAMED_GROUP_FFDHE2048,
        TLS_NAMED_GROUP_FFDHE3072,
        TLS_NAMED_GROUP_FFDHE4096,
        TLS_NAMED_GROUP_FFDHE6144,
        TLS_NAMED_GROUP_FFDHE8192
    };
    uint32_t i;
    for(i = 0; i < (uint32_t)(sizeof(preferred_groups) / sizeof(preferred_groups[0])); i++) {
        uint16_t g = preferred_groups[i];
        if(tls13_client_supports_group(ctx, g) && tls13_client_has_key_share_for_group(ctx, g)) {
            return g;
        }
    }
    /* Fallback: choose first client key share we can process with current build. */
    if(ctx != NULL && ctx->client_key_shares != NULL) {
        for(i = 0; i < ctx->client_key_shares_count; i++) {
            uint16_t g = ctx->client_key_shares[i].group;
#if NOXTLS_FEATURE_ML_KEM
            if(tls13_group_is_mlkem(g) || tls13_group_is_hybrid(g)) {
                return g;
            }
#endif
            if(tls13_server_supports_group(g)) {
                return g;
            }
        }
    }

    return 0;
}

/**
 * @brief Select the HRR group
 *
 * @param[in] ctx The context to select the HRR group from
 * @return The selected HRR group
 */
static uint16_t tls13_select_hrr_group(const tls13_context_t *ctx)
{
    uint32_t i;
    if(ctx == NULL || ctx->client_extensions.supported_groups == NULL ||
       ctx->client_extensions.supported_groups->groups == NULL) {
        return 0;
    }
    /*
     * For HRR, select the first server-supported group from the client's
     * supported_groups list so behavior follows client-advertised preference.
     */
    for(i = 0; i < ctx->client_extensions.supported_groups->count; i++) {
        uint16_t group = ctx->client_extensions.supported_groups->groups[i];
        if(tls13_server_supports_group(group)) {
            return group;
        }
    }
    return 0;
}

/**
 * @brief Write a uint16 to a buffer
 *
 * @param[in] buf The buffer to write to
 * @param[in] value The value to write
 */
static void tls13_write_uint16(uint8_t *buf, uint16_t value)
{
    buf[0] = (uint8_t)((value >> 8) & 0xFF);
    buf[1] = (uint8_t)(value & 0xFF);
}

/**
 * @brief Write a uint48 to a buffer
 *
 * @param[in] buf The buffer to write to
 * @param[in] value The value to write
 */
static void tls13_write_uint48(uint8_t *buf, uint64_t value)
{
    buf[0] = (uint8_t)((value >> 40) & 0xFF);
    buf[1] = (uint8_t)((value >> 32) & 0xFF);
    buf[2] = (uint8_t)((value >> 24) & 0xFF);
    buf[3] = (uint8_t)((value >> 16) & 0xFF);
    buf[4] = (uint8_t)((value >> 8) & 0xFF);
    buf[5] = (uint8_t)(value & 0xFF);
}

/**
 * @brief Read a uint16 from a buffer
 *
 * @param[in] buf The buffer to read from
 * @return The value read
 */
static uint16_t tls13_read_uint16(const uint8_t *buf)
{
    return (uint16_t)((buf[0] << 8) | buf[1]);
}

/**
 * @brief Read a uint48 from a buffer
 *
 * @param[in] buf The buffer to read from
 * @return The value read
 */
static uint64_t tls13_read_uint48(const uint8_t *buf)
{
    return ((uint64_t)buf[0] << 40) |
           ((uint64_t)buf[1] << 32) |
           ((uint64_t)buf[2] << 24) |
           ((uint64_t)buf[3] << 16) |
           ((uint64_t)buf[4] << 8) |
           (uint64_t)buf[5];
}

/**
 * @brief Add an ACK range to the context
 *
 * @param[in] ctx The context to add the ACK range to
 * @param[in] epoch The epoch of the ACK range
 * @param[in] seq The sequence number of the ACK range
 */
static void tls13_dtls_ack_range_add(dtls_context_t *ctx, uint16_t epoch, /* NOLINT(bugprone-easily-swappable-parameters): ACK tuple is (epoch,sequence). */
                                     uint64_t seq)
{
    if(ctx == NULL) {
        return;
    }

    if(ctx->ack_ranges_min == NULL || ctx->ack_ranges_max == NULL || ctx->ack_range_capacity == 0) {
        uint8_t limit = ctx->ack_range_limit == 0 ? DTLS_MAX_ACK_RANGES : ctx->ack_range_limit;
        ctx->ack_range_capacity = limit < 4 ? limit : 4;
        ctx->ack_ranges_min = (uint64_t*)noxtls_malloc(sizeof(uint64_t) * ctx->ack_range_capacity);
        ctx->ack_ranges_max = (uint64_t*)noxtls_malloc(sizeof(uint64_t) * ctx->ack_range_capacity);
        if(ctx->ack_ranges_min == NULL || ctx->ack_ranges_max == NULL) {
            if(ctx->ack_ranges_min != NULL) {
                noxtls_free(ctx->ack_ranges_min);
            }
            if(ctx->ack_ranges_max != NULL) {
                noxtls_free(ctx->ack_ranges_max);
            }
            ctx->ack_ranges_min = NULL;
            ctx->ack_ranges_max = NULL;
            ctx->ack_range_capacity = 0;
            ctx->ack_range_count = 0;
            ctx->ack_range_valid = 0;
            return;
        }
    }

    if(!ctx->ack_pending || !ctx->ack_range_valid || (uint16_t)ctx->ack_epoch != epoch ||
       ctx->ack_range_count == 0) {
        ctx->ack_epoch = epoch;
        ctx->ack_ranges_min[0] = seq;
        ctx->ack_ranges_max[0] = seq;
        ctx->ack_range_count = 1;
        ctx->ack_range_valid = 1;
    } else {
        uint8_t merged = 0;
        for(uint8_t i = 0; i < ctx->ack_range_count; i++) {
            uint64_t minv = ctx->ack_ranges_min[i];
            uint64_t maxv = ctx->ack_ranges_max[i];
            if(seq + 1 >= minv && seq <= maxv + 1) {
                if(seq < minv) {
                    ctx->ack_ranges_min[i] = seq;
                }
                if(seq > maxv) {
                    ctx->ack_ranges_max[i] = seq;
                }
                merged = 1;
                break;
            }
        }
        if(!merged) {
            if(ctx->ack_range_count >= ctx->ack_range_capacity) {
                uint8_t limit = ctx->ack_range_limit == 0 ? DTLS_MAX_ACK_RANGES : ctx->ack_range_limit;
                if(ctx->ack_range_capacity >= limit) {
                    for(uint8_t k = 0; k + 1 < ctx->ack_range_count; k++) {
                        ctx->ack_ranges_min[k] = ctx->ack_ranges_min[k + 1];
                        ctx->ack_ranges_max[k] = ctx->ack_ranges_max[k + 1];
                    }
                    if(ctx->ack_range_count > 0) {
                        ctx->ack_range_count--;
                    }
                } else {
                    uint8_t new_capacity = (uint8_t)(ctx->ack_range_capacity << 1);
                    if(new_capacity > limit) {
                        new_capacity = limit;
                    }
                    {
                        size_t new_bytes = sizeof(uint64_t) * new_capacity;
                        size_t copy_bytes = sizeof(uint64_t) * ctx->ack_range_count;
                        uint64_t *new_min = (uint64_t*)noxtls_malloc(new_bytes);
                        uint64_t *new_max = (uint64_t*)noxtls_malloc(new_bytes);
                        if(new_min == NULL || new_max == NULL) {
                            if(new_min != NULL) noxtls_free(new_min);
                            if(new_max != NULL) noxtls_free(new_max);
                            return;
                        }
                        memcpy(new_min, ctx->ack_ranges_min, copy_bytes);
                        memcpy(new_max, ctx->ack_ranges_max, copy_bytes);
                        noxtls_free(ctx->ack_ranges_min);
                        noxtls_free(ctx->ack_ranges_max);
                        ctx->ack_ranges_min = new_min;
                        ctx->ack_ranges_max = new_max;
                        ctx->ack_range_capacity = new_capacity;
                    }
                }
            }
            if(ctx->ack_range_count < ctx->ack_range_capacity) {
                uint8_t idx = ctx->ack_range_count;
                ctx->ack_ranges_min[idx] = seq;
                ctx->ack_ranges_max[idx] = seq;
                ctx->ack_range_count++;
                merged = 1;
                (void)merged;
            } else {
                return;
            }
        }

        for(uint8_t i = 0; i < ctx->ack_range_count; i++) {
            for(uint8_t j = i + 1; j < ctx->ack_range_count; ) {
                uint64_t imin = ctx->ack_ranges_min[i];
                uint64_t imax = ctx->ack_ranges_max[i];
                uint64_t jmin = ctx->ack_ranges_min[j];
                uint64_t jmax = ctx->ack_ranges_max[j];
                if(jmin <= imax + 1 && jmax + 1 >= imin) {
                    if(jmin < imin) {
                        ctx->ack_ranges_min[i] = jmin;
                    }
                    if(jmax > imax) {
                        ctx->ack_ranges_max[i] = jmax;
                    }
                    for(uint8_t k = j; k + 1 < ctx->ack_range_count; k++) {
                        ctx->ack_ranges_min[k] = ctx->ack_ranges_min[k + 1];
                        ctx->ack_ranges_max[k] = ctx->ack_ranges_max[k + 1];
                    }
                    ctx->ack_range_count--;
                } else {
                    j++;
                }
            }
        }
    }

    ctx->ack_range_min = ctx->ack_ranges_min[0];
    ctx->ack_range_max = ctx->ack_ranges_max[0];
    for(uint8_t i = 1; i < ctx->ack_range_count; i++) {
        if(ctx->ack_ranges_min[i] < ctx->ack_range_min) {
            ctx->ack_range_min = ctx->ack_ranges_min[i];
        }
        if(ctx->ack_ranges_max[i] > ctx->ack_range_max) {
            ctx->ack_range_max = ctx->ack_ranges_max[i];
        }
    }
    ctx->ack_seq = ctx->ack_range_max;
}



/**
 * @brief Check if the final ACK window is active
 *
 * @param[in] dctx The DTLS context to check if the final ACK window is active from
 * @return 1 if the final ACK window is active, 0 otherwise
 */
static int tls13_dtls_final_ack_window_active(dtls_context_t *dctx)
{
    uint64_t now;

    if(dctx == NULL || dctx->final_ack_active == 0U || dctx->final_ack_len == 0U) {
        return 0;
    }
    if(dctx->base.time_callback == NULL || dctx->final_ack_until_ms == 0U) {
        return 1;
    }
    now = dctx->base.time_callback(dctx->base.user_data);
    if(now <= dctx->final_ack_until_ms) {
        return 1;
    }
    dctx->final_ack_active = 0U;
    dctx->final_ack_len = 0U;
    dctx->final_ack_until_ms = 0U;
    return 0;
}

/**
 * @brief Resend the retained final ACK
 *
 * @param[in] ctx The context to resend the retained final ACK from
 * @return The return code
 */
static noxtls_return_t tls13_dtls_resend_retained_final_ack(tls13_context_t *ctx)
{
    dtls_context_t *dctx;

    if(ctx == NULL || !tls13_is_dtls(ctx)) {
        return NOXTLS_RETURN_FAILED;
    }
    dctx = &ctx->base;
    if(!tls13_dtls_final_ack_window_active(dctx)) {
        return NOXTLS_RETURN_FAILED;
    }
    return noxtls_tls_send_record(&dctx->base, TLS_RECORD_ACK, dctx->final_ack, dctx->final_ack_len);
}

/**
 * @brief Flush the ACK
 *
 * @param[in] ctx The context to flush the ACK from
 * @param[in] retain_final Whether to retain the final ACK
 * @return The return code
 */
static noxtls_return_t tls13_dtls_flush_ack(tls13_context_t *ctx, uint8_t retain_final)
{
    dtls_context_t *dctx;
    uint32_t body_len;
    uint32_t total_len;
    uint8_t *ack_msg;
    uint32_t offset = 0;
    noxtls_return_t rc;

    if(ctx == NULL || !tls13_is_dtls(ctx)) {
        return NOXTLS_RETURN_SUCCESS;
    }
    dctx = &ctx->base;
    if(dctx->ack_pending == 0U || dctx->ack_range_valid == 0U || dctx->ack_range_count == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    body_len = 2U + 2U + (12U * dctx->ack_range_count) + 2U;
    total_len = body_len + 4U;
    if(total_len > DTLS_MAX_ACK_WIRE_LEN) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    ack_msg = (uint8_t*)noxtls_malloc(total_len);
    if(ack_msg == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    ack_msg[offset++] = TLS_HANDSHAKE_ACK;
    ack_msg[offset++] = (uint8_t)((body_len >> 16) & 0xFF);
    ack_msg[offset++] = (uint8_t)((body_len >> 8) & 0xFF);
    ack_msg[offset++] = (uint8_t)(body_len & 0xFF);
    tls13_write_uint16(ack_msg + offset, (uint16_t)dctx->ack_epoch);
    offset += 2U;
    tls13_write_uint16(ack_msg + offset, dctx->ack_range_count);
    offset += 2U;
    for(uint8_t i = 0; i < dctx->ack_range_count; i++) {
        tls13_write_uint48(ack_msg + offset, dctx->ack_ranges_min[i]);
        offset += 6U;
        tls13_write_uint48(ack_msg + offset, dctx->ack_ranges_max[i]);
        offset += 6U;
    }
    ack_msg[offset++] = 0x00;
    ack_msg[offset++] = 0x00;

    rc = noxtls_tls_send_record(&dctx->base, TLS_RECORD_ACK, ack_msg, offset);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        if(retain_final != 0U) {
            memcpy(dctx->final_ack, ack_msg, offset);
            dctx->final_ack_len = offset;
            dctx->final_ack_active = 1U;
            if(dctx->base.time_callback != NULL) {
                dctx->final_ack_until_ms = dctx->base.time_callback(dctx->base.user_data) + DTLS_FINAL_ACK_RETENTION_MS;
            } else {
                dctx->final_ack_until_ms = 0U;
            }
        }
        dctx->ack_pending = 0U;
        dctx->ack_range_valid = 0U;
        dctx->ack_range_count = 0U;
    }

    noxtls_free(ack_msg);
    return rc;
}

/**
 * @brief Note the flight acked
 *
 * @param[in] dctx The DTLS context to note the flight acked from
 * @return void
 */
static void tls13_dtls_note_flight_acked(dtls_context_t *dctx)
{
    uint64_t now;
    uint32_t sample;
    uint32_t rto;

    if(dctx == NULL || dctx->base.time_callback == NULL || dctx->last_flight_sent_ms == 0U) {
        return;
    }

    now = dctx->base.time_callback(dctx->base.user_data);
    if(now <= dctx->last_flight_sent_ms) {
        return;
    }

    sample = (uint32_t)(now - dctx->last_flight_sent_ms);

    if(dctx->rtt_estimator_valid == 0U) {
        dctx->smoothed_rtt_ms = sample;
        dctx->rttvar_ms = sample / 2U;
        if(dctx->rttvar_ms == 0U) {
            dctx->rttvar_ms = 1U;
        }
        dctx->rtt_estimator_valid = 1U;
    } else {
        uint32_t srtt = dctx->smoothed_rtt_ms;
        uint32_t rttvar = dctx->rttvar_ms;
        uint32_t err = (srtt > sample) ? (srtt - sample) : (sample - srtt);
        dctx->rttvar_ms = (uint32_t)(((uint64_t)3U * rttvar + err) / 4U);
        dctx->smoothed_rtt_ms = (uint32_t)(((uint64_t)7U * srtt + sample) / 8U);
        if(dctx->rttvar_ms == 0U) {
            dctx->rttvar_ms = 1U;
        }
    }

    rto = dctx->smoothed_rtt_ms + (4U * dctx->rttvar_ms);
    if(rto < 1000u) {
        rto = 1000u;
    }
    if(rto > 60000u) {
        rto = 60000u;
    }
    dctx->retransmit_base_timeout_ms = rto;
    dctx->retransmit_timeout_ms = rto;
}


/**
 * @brief Check if the context is a DTLS context
 *
 * @param[in] ctx The context to check if the context is a DTLS context from
 * @return 1 if the context is a DTLS context, 0 otherwise
 */
static int tls13_is_dtls(const tls13_context_t *ctx)
{
#if NOXTLS_FEATURE_DTLS
    return (ctx != NULL && ctx->base.base.version == DTLS_VERSION_1_3);
#else
    (void)ctx;
    return 0;
#endif
}

/**
 * @brief Parse the raw extension list
 *
 * @param[in] data The data to parse the raw extension list from
 * @param[in] data_len The length of the data to parse the raw extension list from
 * @param[out] extensions The extensions to parse the raw extension list into
 * @return The return code
 */
static noxtls_return_t tls13_parse_raw_extension_list(const uint8_t *data, uint32_t data_len,
                                                       tls_extensions_t *extensions)
{
    uint32_t offset = 0;
    uint32_t extensions_len;
    uint32_t max_extensions = 16U;

    if(data == NULL || extensions == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    memset(extensions, 0, sizeof(*extensions));
    if(data_len < 2U) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    extensions_len = ((uint32_t)data[0] << 8) | data[1];
    offset = 2U;
    if(extensions_len != data_len - 2U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(extensions_len == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    extensions->extensions = (tls_extension_t*)calloc(max_extensions, sizeof(tls_extension_t));
    if(extensions->extensions == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    while(offset < data_len) {
        tls_extension_t *ext;
        uint16_t ext_len;
        if(offset + 4U > data_len) {
            noxtls_tls_extensions_free(extensions);
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(extensions->count >= max_extensions) {
            uint32_t new_max = max_extensions * 2U;
            tls_extension_t *new_exts = (tls_extension_t*)realloc(extensions->extensions,
                                                                  new_max * sizeof(tls_extension_t));
            if(new_exts == NULL) {
                noxtls_tls_extensions_free(extensions);
                return NOXTLS_RETURN_FAILED;
            }
            memset(new_exts + max_extensions, 0, (new_max - max_extensions) * sizeof(tls_extension_t));
            extensions->extensions = new_exts;
            max_extensions = new_max;
        }

        ext = &extensions->extensions[extensions->count];
        ext->type = ((uint16_t)data[offset] << 8) | data[offset + 1];
        ext_len = ((uint16_t)data[offset + 2] << 8) | data[offset + 3];
        ext->length = ext_len;
        offset += 4U;
        if(offset + ext_len > data_len) {
            noxtls_tls_extensions_free(extensions);
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(ext_len > 0U) {
            ext->data = (uint8_t*)malloc(ext_len);
            if(ext->data == NULL) {
                noxtls_tls_extensions_free(extensions);
                return NOXTLS_RETURN_FAILED;
            }
            memcpy(ext->data, data + offset, ext_len);
        }
        offset += ext_len;
        extensions->count++;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief HKDF expand label
 *
 * @param[in] ctx The context to HKDF expand the label from
 * @param[in] hash_algo The hash algorithm to use for the HKDF expand label
 * @param[in] secret The secret to use for the HKDF expand label
 * @param[in] secret_len The length of the secret to use for the HKDF expand label
 * @param[in] label The label to use for the HKDF expand label
 * @param[in] context The context to use for the HKDF expand label
 * @param[in] context_len The length of the context to use for the HKDF expand label
 * @param[out] output The output to use for the HKDF expand label
 * @param[in] output_len The length of the output to use for the HKDF expand label
 * @return The return code
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
 * @brief Derive the secret
 *
 * @param[in] ctx The context to derive the secret from
 * @param[in] hash_algo The hash algorithm to use for the derive secret
 * @param[in] secret The secret to use for the derive secret
 * @param[in] secret_len The length of the secret to use for the derive secret
 * @param[in] label The label to use for the derive secret
 * @param[in] label_len The length of the label to use for the derive secret
 * @param[in] messages The messages to use for the derive secret
 * @param[in] messages_len The length of the messages to use for the derive secret
 * @param[out] output The output to use for the derive secret
 * @param[in] output_len The length of the output to use for the derive secret
 * @return The return code
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
 * @brief Check if the client has a key share
 *
 * @param[in] ctx The context to check if the client has a key share from
 * @param[in] group The group to check if the client has a key share from
 * @return 1 if the client has a key share, 0 otherwise
 */
static int tls13_client_has_key_share(const tls13_context_t *ctx, uint16_t group)
{
    if(ctx == NULL) {
        return 0;
    }
    for(uint32_t i = 0; i < ctx->client_key_shares_count; i++) {
        if(ctx->client_key_shares[i].group == group) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Send the hello retry request
 *
 * @param[in] ctx The context to send the hello retry request from
 * @param[in] cookie The cookie to send the hello retry request from
 * @param[in] cookie_len The length of the cookie to send the hello retry request from
 * @param[in] selected_group The selected group to send the hello retry request from
 * @param[out] hrr_out The output to send the hello retry request from
 * @param[in] hrr_out_len The length of the output to send the hello retry request from
 * @return The return code
 *
 * NOLINTBEGIN(bugprone-easily-swappable-parameters) 
 */
static noxtls_return_t tls13_send_hello_retry_request_dtls(tls13_context_t *ctx,
                                                           const uint8_t *cookie,
                                                           uint16_t cookie_len,
                                                           uint16_t selected_group, /* NOLINT(bugprone-easily-swappable-parameters): HRR carries (cookie_len,selected_group) per extension layout. */
                                                           uint8_t *hrr_out,
                                                           uint32_t *hrr_out_len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    uint8_t *hrr = ctx->handshake_workspace;
    if(hrr == NULL) {
        hrr = (uint8_t*)noxtls_malloc(TLS_HELLO_RETRY_REQUEST_MAX_SIZE);
        if(hrr == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    uint32_t offset = 0;
    static const uint8_t hrr_random[TLS_RANDOM_SIZE] = {
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
    };

    hrr[offset++] = TLS_HANDSHAKE_SERVER_HELLO;
    hrr[offset++] = 0x00;
    hrr[offset++] = 0x00;
    hrr[offset++] = 0x00;
    if(tls13_is_dtls(ctx)) {
        hrr[offset++] = (DTLS_VERSION_1_2 >> 8) & 0xFF;
        hrr[offset++] = DTLS_VERSION_1_2 & 0xFF;
    } else {
        hrr[offset++] = (TLS_VERSION_1_2 >> 8) & 0xFF;
        hrr[offset++] = TLS_VERSION_1_2 & 0xFF;
    }
    memcpy(hrr + offset, hrr_random, sizeof(hrr_random));
    offset += sizeof(hrr_random);
    hrr[offset++] = 0x00; /* legacy session id */
    hrr[offset++] = (ctx->cipher_suite >> 8) & 0xFF;
    hrr[offset++] = ctx->cipher_suite & 0xFF;
    hrr[offset++] = 0x00; /* legacy compression */

    /* Extensions length placeholder */
    uint32_t ext_start = offset;
    hrr[offset++] = 0x00;
    hrr[offset++] = 0x00;

    /* Supported Versions extension */
    hrr[offset++] = (TLS_EXTENSION_SUPPORTED_VERSIONS >> 8) & 0xFF;
    hrr[offset++] = TLS_EXTENSION_SUPPORTED_VERSIONS & 0xFF;
    hrr[offset++] = 0x00;
    hrr[offset++] = 0x02;
    if(tls13_is_dtls(ctx)) {
        hrr[offset++] = (DTLS_VERSION_1_3 >> 8) & 0xFF;
        hrr[offset++] = DTLS_VERSION_1_3 & 0xFF;
    } else {
        hrr[offset++] = (TLS_VERSION_1_3 >> 8) & 0xFF;
        hrr[offset++] = TLS_VERSION_1_3 & 0xFF;
    }

    if(selected_group != 0) {
        hrr[offset++] = (TLS_EXTENSION_KEY_SHARE >> 8) & 0xFF;
        hrr[offset++] = TLS_EXTENSION_KEY_SHARE & 0xFF;
        hrr[offset++] = 0x00;
        hrr[offset++] = 0x02;
        hrr[offset++] = (selected_group >> 8) & 0xFF;
        hrr[offset++] = selected_group & 0xFF;
    }

    /* Cookie extension */
    if(tls13_is_dtls(ctx) && cookie != NULL && cookie_len > 0) {
        uint16_t cookie_ext_len = (uint16_t)(2U + cookie_len);
        hrr[offset++] = (TLS_EXTENSION_COOKIE >> 8) & 0xFF;
        hrr[offset++] = TLS_EXTENSION_COOKIE & 0xFF;
        hrr[offset++] = (cookie_ext_len >> 8) & 0xFF;
        hrr[offset++] = cookie_ext_len & 0xFF;
        hrr[offset++] = (cookie_len >> 8) & 0xFF;
        hrr[offset++] = cookie_len & 0xFF;
        memcpy(hrr + offset, cookie, cookie_len);
        offset += cookie_len;
    }

    uint32_t ext_len = offset - ext_start - 2;
    hrr[ext_start] = (uint8_t)((ext_len >> 8) & 0xFF);
    hrr[ext_start + 1] = (uint8_t)(ext_len & 0xFF);

    uint32_t hs_len = offset - 4;
    hrr[1] = (uint8_t)((hs_len >> 16) & 0xFF);
    hrr[2] = (uint8_t)((hs_len >> 8) & 0xFF);
    hrr[3] = (uint8_t)(hs_len & 0xFF);

    if(hrr_out != NULL && hrr_out_len != NULL) {
        if(*hrr_out_len < offset) {
            if(hrr != ctx->handshake_workspace) NOXTLS_SECURE_FREE(hrr, TLS_HELLO_RETRY_REQUEST_MAX_SIZE);
            else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            *hrr_out_len = offset;
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(hrr_out, hrr, offset);
        *hrr_out_len = offset;
    }

    noxtls_debug_printf("[TLS13_DEBUG] send_hrr hex:\n");
    for(uint32_t i = 0; i < offset; i++) {
        noxtls_debug_printf("%02X", hrr[i]);
        if(((i + 1U) & 31U) == 0U) {
            noxtls_debug_printf("\n");
        }
    }
    if((offset & 31U) != 0U) {
        noxtls_debug_printf("\n");
    }

    noxtls_return_t rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, hrr, offset);
    if(hrr != ctx->handshake_workspace) NOXTLS_SECURE_FREE(hrr, TLS_HELLO_RETRY_REQUEST_MAX_SIZE);
    else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return rc;
}

/**
 * @brief Reset the transcript for the hello retry request
 *
 * @param[in] ctx The context to reset the transcript for the hello retry request from
 * @param[in] hash_algo The hash algorithm to use for the reset transcript for the hello retry request
 * @param[in] hash_len The length of the hash to use for the reset transcript for the hello retry request
 * @return The return code
 */
static noxtls_return_t tls13_reset_transcript_for_hrr(tls13_context_t *ctx,
                                                      noxtls_hash_algos_t hash_algo, /* NOLINT(bugprone-easily-swappable-parameters): transcript reset uses explicit (algo,hash_len). */
                                                      uint32_t hash_len)
{
    uint8_t hash[TLS_MAX_SECRET_LEN];
    uint32_t out_len = sizeof(hash);
    uint8_t *msg;
    uint32_t msg_len;
    noxtls_return_t rc;

    if(ctx == NULL || ctx->handshake_messages_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                             hash, &out_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(out_len != hash_len) {
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_debug_printf("[TLS13_DEBUG] reset_transcript_for_hrr: hash=");
    for(uint32_t i = 0; i < out_len; i++) {
        noxtls_debug_printf("%02X", hash[i]);
    }
    noxtls_debug_printf(" len=%u\n", (unsigned)out_len);

    msg_len = 4 + out_len;
    msg = (uint8_t*)malloc(msg_len);
    if(msg == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    msg[0] = TLS_HANDSHAKE_MESSAGE_HASH;
    msg[1] = (uint8_t)((out_len >> 16) & 0xFF);
    msg[2] = (uint8_t)((out_len >> 8) & 0xFF);
    msg[3] = (uint8_t)(out_len & 0xFF);
    memcpy(msg + 4, hash, out_len);

    if(ctx->handshake_messages) {
        free(ctx->handshake_messages);
    }
    ctx->handshake_messages = msg;
    ctx->handshake_messages_len = msg_len;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Send the handshake message
 *
 * @param[in] ctx The context to send the handshake message from
 * @param[in] msg The message to send the handshake message from
 * @param[in] msg_len The length of the message to send the handshake message from
 * @return The return code
 */
static noxtls_return_t tls13_send_handshake_message(tls13_context_t *ctx, const uint8_t *msg, uint32_t msg_len)
{
    if(ctx == NULL || msg == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->handshake_encrypted) {
        return tls13_send_encrypted_handshake(ctx, msg, msg_len);
    }
    return noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, msg, msg_len);
}

/**
 * @brief Check if the message is an ack message
 *
 * @param[in] msg The message to check if it is an ack message from
 * @param[in] len The length of the message to check if it is an ack message from
 * @return 1 if the message is an ack message, 0 otherwise
 */
static int tls13_is_ack_message(const uint8_t *msg, uint32_t len)
{
    if(msg == NULL || len == 0) {
        return 0;
    }
    return (msg[0] == TLS_HANDSHAKE_ACK);
}

/**
 * @brief Handle the ack message
 *
 * @param[in] ctx The context to handle the ack message from
 * @param[in] msg The message to handle the ack message from
 * @param[in] len The length of the message to handle the ack message from
 * @return void
 */
static void tls13_dtls_handle_ack(tls13_context_t *ctx, const uint8_t *msg, uint32_t len)
{
    uint32_t body_len;
    uint32_t offset = 4;
    uint16_t epoch;
    uint16_t range_count;
    uint64_t min_seq = UINT64_MAX;
    uint64_t max_seq = 0;
    uint64_t ranges_min_stack[DTLS_MAX_ACK_RANGES];
    uint64_t ranges_max_stack[DTLS_MAX_ACK_RANGES];
    uint16_t stored_ranges = 0;

    if(ctx == NULL || msg == NULL || len < 8 || msg[0] != TLS_HANDSHAKE_ACK) {
        return;
    }

    body_len = ((uint32_t)msg[1] << 16) | ((uint32_t)msg[2] << 8) | msg[3];
    if(len < body_len + 4) {
        return;
    }

    epoch = tls13_read_uint16(msg + offset);
    offset += 2;
    range_count = tls13_read_uint16(msg + offset);
    offset += 2;
    if(range_count == 0) {
        return;
    }
    if(range_count > DTLS_MAX_ACK_RANGES) {
        range_count = DTLS_MAX_ACK_RANGES;
    }

    for(uint16_t i = 0; i < range_count; i++) {
        uint64_t start;
        uint64_t end;
        if(offset + 12 > len) {
            return;
        }
        start = tls13_read_uint48(msg + offset);
        offset += 6;
        end = tls13_read_uint48(msg + offset);
        offset += 6;
        if(start > end) {
            uint64_t tmp = start;
            start = end;
            end = tmp;
        }
        if(start < min_seq) {
            min_seq = start;
        }
        if(end > max_seq) {
            max_seq = end;
        }
        ranges_min_stack[stored_ranges] = start;
        ranges_max_stack[stored_ranges] = end;
        stored_ranges++;
    }

    if(offset + 2 > len) {
        return;
    }

    ctx->base.last_ack_epoch = epoch;
    ctx->base.last_ack_seq = max_seq;
    ctx->base.last_ack_range_min = min_seq;
    ctx->base.last_ack_range_max = max_seq;
    ctx->base.last_ack_range_count = (uint8_t)stored_ranges;
    if(stored_ranges > 0U) {
        size_t range_bytes = sizeof(uint64_t) * stored_ranges;
        uint64_t *new_min = (uint64_t*)realloc(ctx->base.last_ack_ranges_min, range_bytes);
        uint64_t *new_max = (uint64_t*)realloc(ctx->base.last_ack_ranges_max, range_bytes);
        if(new_min != NULL && new_max != NULL) {
            ctx->base.last_ack_ranges_min = new_min;
            ctx->base.last_ack_ranges_max = new_max;
            memcpy(ctx->base.last_ack_ranges_min, ranges_min_stack, range_bytes);
            memcpy(ctx->base.last_ack_ranges_max, ranges_max_stack, range_bytes);
        } else {
            if(new_min != NULL) {
                ctx->base.last_ack_ranges_min = new_min;
            }
            if(new_max != NULL) {
                ctx->base.last_ack_ranges_max = new_max;
            }
            ctx->base.last_ack_range_count = 0;
        }
    }
    if(ctx->base.flight_has_range &&
       ctx->base.flight_epoch == epoch &&
       min_seq <= ctx->base.flight_min_seq &&
       max_seq >= ctx->base.flight_max_seq) {
        tls13_dtls_note_flight_acked(&ctx->base);
        ctx->base.flight_buffer_len = 0;
        ctx->base.flight_has_range = 0;
        ctx->cid_request_outstanding = 0;
        ctx->cid_new_outstanding = 0;
    }
}

/**
 * @brief Process the client key share internally
 *
 * @param[in] ctx The context to process the client key share internally from
 * @return The return code
 */
static noxtls_return_t tls13_process_client_key_share_internal(tls13_context_t *ctx)
{
    const tls13_key_share_entry_t *share = NULL;
    tls_ecdhe_context_t *ecdhe_ctx;
    ecc_point_t peer_public_key;
    noxtls_return_t rc;
    uint32_t i;
    uint64_t step_t0 = 0U;

    if(ctx == NULL || ctx->client_key_shares_count == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    if(tls13_group_is_mlkem(ctx->selected_kex_group) || tls13_group_is_hybrid(ctx->selected_kex_group)) {
        if(ctx->hybrid_shared_secret_len == 0) {
            return NOXTLS_RETURN_FAILED;
        }
        step_t0 = tls13_profile_now_us();
        ctx->last_accept_timing.process_client_key_share_compute_secret_us = 0U;
        rc = tls13_derive_handshake_keys(ctx, ctx->hybrid_shared_secret, ctx->hybrid_shared_secret_len);
        ctx->last_accept_timing.process_client_key_share_derive_keys_us = tls13_profile_elapsed_us(step_t0);
        return rc;
    }
    if(tls13_group_is_ffdhe(ctx->selected_kex_group)) {
        if(ctx->ffdhe_shared_secret_len == 0) {
            return NOXTLS_RETURN_FAILED;
        }
        step_t0 = tls13_profile_now_us();
        ctx->last_accept_timing.process_client_key_share_compute_secret_us = 0U;
        rc = tls13_derive_handshake_keys(ctx, ctx->ffdhe_shared_secret, ctx->ffdhe_shared_secret_len);
        ctx->last_accept_timing.process_client_key_share_derive_keys_us = tls13_profile_elapsed_us(step_t0);
        return rc;
    }

    for(i = 0; i < ctx->client_key_shares_count; i++) {
        if(ctx->client_key_shares[i].group == ctx->selected_kex_group) {
            share = &ctx->client_key_shares[i];
            break;
        }
    }
    if(share == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
    if(ecdhe_ctx == NULL || ecdhe_ctx->named_group != share->group) {
        if(ecdhe_ctx != NULL) {
            noxtls_tls_ecdhe_context_free(ecdhe_ctx);
            free(ecdhe_ctx);
        }
        ecdhe_ctx = (tls_ecdhe_context_t*)malloc(sizeof(tls_ecdhe_context_t));
        if(ecdhe_ctx == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        if(noxtls_tls_ecdhe_context_init(ecdhe_ctx, share->group) != NOXTLS_RETURN_SUCCESS ||
           noxtls_tls_ecdhe_generate_ephemeral_key(ecdhe_ctx) != NOXTLS_RETURN_SUCCESS) {
            noxtls_tls_ecdhe_context_free(ecdhe_ctx);
            free(ecdhe_ctx);
            return NOXTLS_RETURN_FAILED;
        }
        ctx->ecdhe_ctx = ecdhe_ctx;
    }

    if(share->group == TLS_NAMED_GROUP_X25519) {
        noxtls_debug_printf("[TLS13_DEBUG] server key_share: group=0x%04X key_exchange_len=%u expected=%u\n",
                            share->group, share->key_exchange_len, NOXTLS_X25519_KEY_SIZE);
        if(share->key_exchange_len != NOXTLS_X25519_KEY_SIZE) {
            return NOXTLS_RETURN_FAILED;
        }
        step_t0 = tls13_profile_now_us();
        rc = noxtls_tls_ecdhe_compute_shared_secret_x25519(ecdhe_ctx, share->key_exchange);
        ctx->last_accept_timing.process_client_key_share_compute_secret_us = tls13_profile_elapsed_us(step_t0);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    } else if(share->group == TLS_NAMED_GROUP_X448) {
        noxtls_debug_printf("[TLS13_DEBUG] server key_share: group=0x%04X key_exchange_len=%u expected=%u\n",
                            share->group, share->key_exchange_len, NOXTLS_X448_KEY_SIZE);
        if(share->key_exchange_len != NOXTLS_X448_KEY_SIZE) {
            return NOXTLS_RETURN_FAILED;
        }
        step_t0 = tls13_profile_now_us();
        rc = noxtls_tls_ecdhe_compute_shared_secret_x448(ecdhe_ctx, share->key_exchange);
        ctx->last_accept_timing.process_client_key_share_compute_secret_us = tls13_profile_elapsed_us(step_t0);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    } else {
        rc = noxtls_tls_decode_ecc_point_uncompressed(share->key_exchange, share->key_exchange_len,
                                               &peer_public_key, ecdhe_ctx->curve_type);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        step_t0 = tls13_profile_now_us();
        rc = noxtls_tls_ecdhe_compute_shared_secret(ecdhe_ctx, &peer_public_key);
        ctx->last_accept_timing.process_client_key_share_compute_secret_us = tls13_profile_elapsed_us(step_t0);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    if(ecdhe_ctx->shared_secret == NULL || ecdhe_ctx->shared_secret_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    step_t0 = tls13_profile_now_us();
    rc = tls13_derive_handshake_keys(ctx, ecdhe_ctx->shared_secret, ecdhe_ctx->shared_secret_len);
    ctx->last_accept_timing.process_client_key_share_derive_keys_us = tls13_profile_elapsed_us(step_t0);
    return rc;
}



/**
 * @brief Set the NSS key log file path for Wireshark decryption (SSLKEYLOGFILE format).
 * @param[in] path Filesystem path, or NULL/empty to clear the explicit path.
 */
void noxtls_tls13_set_keylog_file(const char *path)
{
    if(path == NULL || *path == '\0') {
        tls13_keylog_path[0] = '\0';
        return;
    }
    {
        size_t path_len = strlen(path);
        size_t copy_len = path_len < (sizeof(tls13_keylog_path) - 1)
            ? path_len
            : (sizeof(tls13_keylog_path) - 1);
        memcpy(tls13_keylog_path, path, copy_len);
        tls13_keylog_path[copy_len] = '\0';
    }
}

/**
 * @brief Write the key log to the file
 *
 * @param[in] label The label to write the key log to the file from
 * @param[in] client_random The client random to write the key log to the file from
 * @param[in] secret The secret to write the key log to the file from
 * @param[in] secret_len The length of the secret to write the key log to the file from
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
 * @brief Append a handshake message to the handshake message buffer
 *
 * @param[in] ctx The context to append the handshake message to the handshake message buffer from
 * @param[in] data The data to append the handshake message to the handshake message buffer from
 * @param[in] len The length of the data to append the handshake message to the handshake message buffer from
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context or data is NULL, or NOXTLS_RETURN_FAILED if the handshake message cannot be appended
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
    if(len == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }
    uint32_t new_len = ctx->handshake_messages_len + len;
    uint8_t *new_buffer = (uint8_t*)realloc(ctx->handshake_messages, new_len);
    if(new_buffer == NULL) {
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
 * @brief Release the handshake certificate buffer
 *
 * @param[in] ctx The context to release the handshake certificate buffer from
 * @param[in] certificate The certificate to release the handshake certificate buffer from
 */
void tls13_release_handshake_cert_buffer(tls13_context_t *ctx, uint8_t *certificate)
{
    if(certificate == NULL) {
        return;
    }
    if(ctx != NULL && certificate == ctx->handshake_workspace) {
        memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return;
    }
    NOXTLS_SECURE_FREE(certificate, TLS_HANDSHAKE_WORKSPACE_SIZE);
}

/**
 * @brief Send the middlebox compatibility CCS
 *
 * @param[in] ctx The context to send the middlebox compatibility CCS from
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, or 
 *         NOXTLS_RETURN_TLS_ERROR if the middlebox compatibility CCS cannot be sent
 */
static noxtls_return_t tls13_send_middlebox_compat_ccs(tls13_context_t *ctx)
{
    uint8_t ccs = TLS_RECORD_CCS_PAYLOAD;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    /* RFC 8446 Appendix D.4: optional dummy CCS for middlebox compatibility. */
    return noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_CHANGE_CIPHER_SPEC, &ccs, 1);
}

/**
 * @brief Handle the peer compatibility CCS
 *
 * @param[in] ctx The context to handle the peer compatibility CCS from
 * @param[in] record The record to handle the peer compatibility CCS from
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context or record is NULL, or 
 *         NOXTLS_RETURN_TLS_ERROR if the peer compatibility CCS cannot be handled
 */
static noxtls_return_t tls13_handle_peer_compat_ccs(tls13_context_t *ctx, const tls_record_t *record)
{
    if(ctx == NULL || record == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    /* RFC 8446 middlebox CCS compatibility only allows a single-byte payload 0x01. */
    if(record->length != 1U || record->data == NULL || record->data[0] != TLS_RECORD_CCS_PAYLOAD) {
        return NOXTLS_RETURN_TLS_ERROR;
    }
    /* Reject repeated CCS during handshake to avoid CCS flooding patterns (CVE-2020-25648 style). */
    if(ctx->peer_compat_ccs_seen != 0U) {
        return NOXTLS_RETURN_TLS_ERROR;
    }
    ctx->peer_compat_ccs_seen = 1U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Check if the client supports a signature scheme
 *
 * @param[in] ctx The context to check if the client supports a signature scheme from
 * @param[in] sig_scheme The signature scheme to check if the client supports
 * @return 1 if the client supports the signature scheme, 0 otherwise
 */
static int tls13_client_supports_signature_scheme(const tls13_context_t *ctx, uint16_t sig_scheme)
{
    uint32_t i;
    const tls_signature_algorithms_extension_t *sigalgs;

    if(ctx == NULL) {
        return 0;
    }

    sigalgs = ctx->client_extensions.signature_algorithms;
    if(sigalgs == NULL || sigalgs->algorithms == NULL || sigalgs->count == 0) {
        /*
         * If client did not advertise signature_algorithms, keep prior behavior
         * and let CertificateVerify proceed with local defaults.
         */
        return 1;
    }

    for(i = 0; i < sigalgs->count; i++) {
        if(sigalgs->algorithms[i] == sig_scheme) {
            return 1;
        }
    }
    return 0;
}

#if !NOXTLS_CFG_TLS13_ALLOW_RSA_PKCS1_CERTVERIFY
/**
 * RFC 8446: rsa_pkcs1_* schemes MUST NOT be used with TLS 1.3 CertificateVerify.
 * tlsfuzzer test_tls13_pkcs_signature.py expects handshake_failure when the client
 * offers only these legacy PKCS#1 v1.5 RSA combinations.
 */
/**
 * @brief Check if the RSA PKCS#1 v1.5 signature scheme is deprecated for TLS 1.3 CertificateVerify
 *
 * @param[in] scheme The signature scheme to check if the RSA PKCS#1 v1.5 signature scheme is deprecated for TLS 1.3 CertificateVerify
 * @return 1 if the RSA PKCS#1 v1.5 signature scheme is deprecated for TLS 1.3 CertificateVerify, 0 otherwise
 */
static int tls13_sig_scheme_is_deprecated_rsa_pkcs1_tls13(uint16_t scheme)
{
    switch(scheme) {
        case 0x0101u: /* rsa_md5 */
        case 0x0201u: /* rsa_pkcs1_sha1 */
        case 0x0301u: /* rsa_pkcs1_sha224 */
        case 0x0401u: /* rsa_pkcs1_sha256 */
        case 0x0501u: /* rsa_pkcs1_sha384 */
        case 0x0601u: /* rsa_pkcs1_sha512 */
            return 1;
        default:
            return 0;
    }
}
#endif

/**
 * @brief Check if the ECDSA signature scheme matches the curve
 *
 * @param[in] curve_kind The curve kind to check if the ECDSA signature scheme matches
 * @param[in] scheme The signature scheme to check if the ECDSA signature scheme matches the curve
 * @return 1 if the ECDSA signature scheme matches the curve, 0 otherwise
 */
static int tls13_ecdsa_scheme_matches_curve(ecc_curve_t curve_kind, uint16_t scheme)
{
    switch(curve_kind) {
        case NOXTLS_ECC_SECP256R1:
            return (scheme == TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256) ? 1 : 0;
        case NOXTLS_ECC_SECP384R1:
            return (scheme == TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384) ? 1 : 0;
        case NOXTLS_ECC_SECP521R1:
            return (scheme == TLS_SIGSCHEME_ECDSA_SECP521R1_SHA512) ? 1 : 0;
        case NOXTLS_ECC_BP256R1:
            return (scheme == TLS_SIGSCHEME_ECDSA_BRAINPOOLP256R1_TLS13_SHA256) ? 1 : 0;
        case NOXTLS_ECC_BP384R1:
            return (scheme == TLS_SIGSCHEME_ECDSA_BRAINPOOLP384R1_TLS13_SHA384) ? 1 : 0;
        case NOXTLS_ECC_BP512R1:
            return (scheme == TLS_SIGSCHEME_ECDSA_BRAINPOOLP512R1_TLS13_SHA512) ? 1 : 0;
        default:
            return 0;
    }
}

/**
 * @brief Check if the server can sign a signature scheme
 *
 * @param[in] ctx The context to check if the server can sign a signature scheme from
 * @param[in] scheme The signature scheme to check if the server can sign
 * @return 1 if the server can sign the signature scheme, 0 otherwise
 */
static int tls13_server_can_sign_scheme(const tls13_context_t *ctx, uint16_t scheme)
{
    const ecc_key_t *eckey;

    if(ctx == NULL) {
        return 0;
    }
#if !NOXTLS_CFG_TLS13_ALLOW_RSA_PKCS1_CERTVERIFY
    if(tls13_sig_scheme_is_deprecated_rsa_pkcs1_tls13(scheme)) {
        return 0;
    }
#endif
    /*
     * ECDSA-capable schemes must be checked before RSA: tls13_pick_server_ecdsa_identity_from_matrix()
     * may install an ECDSA identity (cert + private key) while RSA material remains loaded for TLS 1.2
     * fallback. tlsfuzzer test_tls13_minerva.py advertises ECDSA-only signature_algorithms; if RSA is
     * consulted first, no scheme matches and the server aborts with handshake_failure before ServerHello.
     */
    eckey = (const ecc_key_t *)ctx->server_private_ecdsa;
    if(eckey != NULL && eckey->curve != NULL &&
       tls13_ecdsa_scheme_matches_curve(eckey->curve_kind, scheme)) {
        return 1;
    }
    if(ctx->server_private_rsa != NULL) {
        if(scheme == TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256 ||
           scheme == 0x0805u ||
           scheme == 0x0806u) {
            return 1;
        }
    }
    if(ctx->server_cert_use_ed25519 != 0U && scheme == TLS_SIGSCHEME_ED25519) {
        return 1;
    }
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
    if(ctx->server_cert_use_ed448 != 0U && scheme == TLS_SIGSCHEME_ED448) {
        return 1;
    }
#endif
    if(ctx->server_cert_use_mldsa) {
#if NOXTLS_FEATURE_ML_DSA
        uint16_t mldsa_scheme = (ctx->server_private_mldsa_param == NOXTLS_MLDSA_44) ? TLS_SIGSCHEME_MLDSA44 :
                                (ctx->server_private_mldsa_param == NOXTLS_MLDSA_65) ? TLS_SIGSCHEME_MLDSA65 :
                                TLS_SIGSCHEME_MLDSA87;
        return (scheme == mldsa_scheme) ? 1 : 0;
#else
        return 0;
#endif
    }
    if(ctx->server_cert_use_slhdsa) {
#if NOXTLS_FEATURE_SLH_DSA
        return (scheme == tls13_slhdsa_param_to_sig_scheme(ctx->server_private_slhdsa_param)) ? 1 : 0;
#else
        return 0;
#endif
    }
    if(ctx->server_cert_use_falcon) {
#if NOXTLS_FEATURE_FALCON
        uint16_t falcon_scheme = (ctx->server_private_falcon_param == NOXTLS_FALCON_512)
                                     ? TLS_SIGSCHEME_FALCON512
                                     : TLS_SIGSCHEME_FALCON1024;
        return (scheme == falcon_scheme) ? 1 : 0;
#else
        return 0;
#endif
    }
    return 0;
}

/**
 * @brief Select the server certificate signature scheme for legacy support
 *
 * @param[in] ctx The context to select the server certificate signature scheme for legacy support from
 * @return The server certificate signature scheme for legacy support
 */
static uint16_t tls13_select_server_certificate_sig_scheme_legacy(const tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return 0;
    }
    if(ctx->server_private_rsa != NULL) {
        if(tls13_client_supports_signature_scheme(ctx, TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256)) {
            return TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256;
        }
        if(tls13_client_supports_signature_scheme(ctx, 0x0805u)) { /* rsa_pss_rsae_sha384 */
            return 0x0805u;
        }
        if(tls13_client_supports_signature_scheme(ctx, 0x0806u)) { /* rsa_pss_rsae_sha512 */
            return 0x0806u;
        }
        return 0;
    }
    if(ctx->server_private_ecdsa != NULL) {
        const ecc_key_t *eckey = (const ecc_key_t *)ctx->server_private_ecdsa;
        uint32_t coord_size = (eckey->curve != NULL) ? eckey->curve->size : 32U;
        if(tls13_ecdsa_scheme_matches_curve(eckey->curve_kind,
                                            TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256) &&
           coord_size == 32U &&
           tls13_client_supports_signature_scheme(ctx, TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256)) {
            return TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256;
        }
        if(tls13_ecdsa_scheme_matches_curve(eckey->curve_kind,
                                            TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384) &&
           coord_size == 48U &&
           tls13_client_supports_signature_scheme(ctx, TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384)) {
            return TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384;
        }
        if(tls13_ecdsa_scheme_matches_curve(eckey->curve_kind,
                                            TLS_SIGSCHEME_ECDSA_SECP521R1_SHA512) &&
           coord_size == 66u &&
           tls13_client_supports_signature_scheme(ctx, TLS_SIGSCHEME_ECDSA_SECP521R1_SHA512)) {
            return TLS_SIGSCHEME_ECDSA_SECP521R1_SHA512;
        }
        if(tls13_ecdsa_scheme_matches_curve(eckey->curve_kind,
                                            TLS_SIGSCHEME_ECDSA_BRAINPOOLP256R1_TLS13_SHA256) &&
           coord_size == 32U &&
           tls13_client_supports_signature_scheme(ctx, TLS_SIGSCHEME_ECDSA_BRAINPOOLP256R1_TLS13_SHA256)) {
            return TLS_SIGSCHEME_ECDSA_BRAINPOOLP256R1_TLS13_SHA256;
        }
        if(tls13_ecdsa_scheme_matches_curve(eckey->curve_kind,
                                            TLS_SIGSCHEME_ECDSA_BRAINPOOLP384R1_TLS13_SHA384) &&
           coord_size == 48U &&
           tls13_client_supports_signature_scheme(ctx, TLS_SIGSCHEME_ECDSA_BRAINPOOLP384R1_TLS13_SHA384)) {
            return TLS_SIGSCHEME_ECDSA_BRAINPOOLP384R1_TLS13_SHA384;
        }
        if(tls13_ecdsa_scheme_matches_curve(eckey->curve_kind,
                                            TLS_SIGSCHEME_ECDSA_BRAINPOOLP512R1_TLS13_SHA512) &&
           coord_size == 64U &&
           tls13_client_supports_signature_scheme(ctx, TLS_SIGSCHEME_ECDSA_BRAINPOOLP512R1_TLS13_SHA512)) {
            return TLS_SIGSCHEME_ECDSA_BRAINPOOLP512R1_TLS13_SHA512;
        }
        return 0U;
    }
    if(ctx->server_cert_use_ed25519) {
        return tls13_client_supports_signature_scheme(ctx, TLS_SIGSCHEME_ED25519)
                   ? TLS_SIGSCHEME_ED25519
                   : 0U;
    }
    if(ctx->server_cert_use_ed448) {
        return tls13_client_supports_signature_scheme(ctx, TLS_SIGSCHEME_ED448)
                   ? TLS_SIGSCHEME_ED448
                   : 0U;
    }
    if(ctx->server_cert_use_mldsa) {
#if NOXTLS_FEATURE_ML_DSA
        uint16_t sig_scheme = (ctx->server_private_mldsa_param == NOXTLS_MLDSA_44) ? TLS_SIGSCHEME_MLDSA44 :
                              (ctx->server_private_mldsa_param == NOXTLS_MLDSA_65) ? TLS_SIGSCHEME_MLDSA65 :
                              TLS_SIGSCHEME_MLDSA87;
        return tls13_client_supports_signature_scheme(ctx, sig_scheme) ? sig_scheme : 0U;
#else
        return 0U;
#endif
    }
    if(ctx->server_cert_use_slhdsa) {
#if NOXTLS_FEATURE_SLH_DSA
        uint16_t sig_scheme = tls13_slhdsa_param_to_sig_scheme(ctx->server_private_slhdsa_param);
        return tls13_client_supports_signature_scheme(ctx, sig_scheme) ? sig_scheme : 0U;
#else
        return 0U;
#endif
    }
    if(ctx->server_cert_use_falcon) {
#if NOXTLS_FEATURE_FALCON
        uint16_t sig_scheme = (ctx->server_private_falcon_param == NOXTLS_FALCON_512)
                                  ? TLS_SIGSCHEME_FALCON512
                                  : TLS_SIGSCHEME_FALCON1024;
        return tls13_client_supports_signature_scheme(ctx, sig_scheme) ? sig_scheme : 0U;
#else
        return 0U;
#endif
    }
    return 0U;
}

/**
 * @brief Pick the server ECDSA identity from the matrix
 *
 * @param[in] ctx The context to pick the server ECDSA identity from
 */
static void tls13_pick_server_ecdsa_identity_from_matrix(tls13_context_t *ctx)
{
    uint32_t ai;
    uint32_t mi;
    const tls_signature_algorithms_extension_t *sigalgs;

    if(ctx == NULL || ctx->server_ecdsa_matrix_count == 0U) {
        return;
    }

    sigalgs = ctx->client_extensions.signature_algorithms;
    if(sigalgs != NULL && sigalgs->algorithms != NULL && sigalgs->count > 0U) {
        /*
         * Matrix-major: prefer identities in stable load order (e.g. P-256 before P-521),
         * then the earliest client signature_algorithms entry compatible with that identity.
         * Client-first ordering would bind tlsfuzzer "sanity" to ecdsa_secp521r1_sha512 when
         * it appears first in the client's list even when a weaker curve is acceptable.
         */
        for(mi = 0; mi < ctx->server_ecdsa_matrix_count; mi++) {
            ecc_key_t *ek = (ecc_key_t *)ctx->server_ecdsa_matrix_keys[mi];
            if(ek == NULL) {
                continue;
            }
            for(ai = 0; ai < sigalgs->count; ai++) {
                uint16_t s = sigalgs->algorithms[ai];
                if(tls13_ecdsa_scheme_matches_curve(ek->curve_kind, s)) {
                    ctx->server_cert = (uint8_t *)(void *)ctx->server_ecdsa_matrix_certs[mi];
                    ctx->server_cert_len = ctx->server_ecdsa_matrix_cert_lens[mi];
                    ctx->server_private_ecdsa = ek;
                    return;
                }
            }
        }
        return;
    }

    ctx->server_cert = (uint8_t *)(void *)ctx->server_ecdsa_matrix_certs[0];
    ctx->server_cert_len = ctx->server_ecdsa_matrix_cert_lens[0];
    ctx->server_private_ecdsa = ctx->server_ecdsa_matrix_keys[0];
}

/**
 * @brief Convert an ECDSA signature scheme to a hash algorithm
 *
 * @param[in] scheme The signature scheme to convert
 * @param[out] out_hash The hash algorithm to convert to
 * @return 1 on success, 0 on failure
 *         NOXTLS_RETURN_NULL if the hash algorithm is NULL, or NOXTLS_RETURN_INVALID_ALGORITHM if the signature scheme is invalid
 */
static int tls13_ecdsa_sig_scheme_to_hash(uint16_t scheme, noxtls_hash_algos_t *out_hash)
{
    if(out_hash == NULL) {
        return 0;
    }
    switch(scheme) {
        case TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256:
        case TLS_SIGSCHEME_ECDSA_BRAINPOOLP256R1_TLS13_SHA256:
            *out_hash = NOXTLS_HASH_SHA_256;
            return 1;
        case TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384:
        case TLS_SIGSCHEME_ECDSA_BRAINPOOLP384R1_TLS13_SHA384:
            *out_hash = NOXTLS_HASH_SHA_384;
            return 1;
        case TLS_SIGSCHEME_ECDSA_SECP521R1_SHA512:
        case TLS_SIGSCHEME_ECDSA_BRAINPOOLP512R1_TLS13_SHA512:
            *out_hash = NOXTLS_HASH_SHA_512;
            return 1;
        default:
            return 0;
    }
}

/* RFC 8446 §4.4.3: CertificateVerify Transcript-Hash uses SignatureScheme hash, not cipher suite. */
/**
 * @brief Get the hash algorithm for the certificate verify hash
 *
 * @param[in] scheme The signature scheme to get the hash algorithm for the certificate verify hash from
 * @param[out] out_hash The hash algorithm to get the hash algorithm for the certificate verify hash into
 * @return 1 on success, 0 on failure
 */
static int tls13_sig_scheme_certificate_verify_hash(uint16_t scheme, noxtls_hash_algos_t *out_hash)
{
    if(out_hash == NULL) {
        return 0;
    }
    if(tls13_ecdsa_sig_scheme_to_hash(scheme, out_hash)) {
        return 1;
    }
    switch(scheme) {
        case TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256:
            *out_hash = NOXTLS_HASH_SHA_256;
            return 1;
        case TLS_SIGSCHEME_LMS_HSS_SHA256:
        case TLS_SIGSCHEME_XMSS_SHA256:
        case TLS_SIGSCHEME_XMSSMT_SHA256:
            *out_hash = NOXTLS_HASH_SHA_256;
            return 1;
        case 0x0805u: /* rsa_pss_rsae_sha384 */
            *out_hash = NOXTLS_HASH_SHA_384;
            return 1;
        case 0x0806u: /* rsa_pss_rsae_sha512 */
            *out_hash = NOXTLS_HASH_SHA_512;
            return 1;
        case TLS_SIGSCHEME_ED25519:
        case TLS_SIGSCHEME_ED448:
            *out_hash = NOXTLS_HASH_SHA_512;
            return 1;
#if NOXTLS_FEATURE_ML_DSA
        case TLS_SIGSCHEME_MLDSA44:
        case TLS_SIGSCHEME_MLDSA65:
        case TLS_SIGSCHEME_MLDSA87:
        case TLS_SIGSCHEME_RSA_PSS_SHA256_MLDSA44:
        case TLS_SIGSCHEME_RSA_PSS_SHA256_MLDSA65:
        case TLS_SIGSCHEME_RSA_PSS_SHA384_MLDSA87:
            *out_hash = NOXTLS_HASH_SHA_512;
            return 1;
#endif
        default:
            break;
    }
#if NOXTLS_FEATURE_SLH_DSA
    if(scheme >= TLS_SIGSCHEME_SLHDSA_SHA2_128S && scheme <= TLS_SIGSCHEME_SLHDSA_SHAKE_256F) {
        *out_hash = NOXTLS_HASH_SHA_512;
        return 1;
    }
#endif
    return 0;
}



/**
 * @brief Max signature octets for a TLS SignatureScheme (for CV message sizing).
 * @param sig_scheme Wire SignatureScheme value.
 * @return Signature capacity in bytes (at least 64 for unknown classical schemes).
 */
static uint32_t tls13_certificate_verify_signature_capacity(uint16_t sig_scheme)
{
#if NOXTLS_FEATURE_SLH_DSA
    if(sig_scheme >= TLS_SIGSCHEME_SLHDSA_SHA2_128S && sig_scheme <= TLS_SIGSCHEME_SLHDSA_SHAKE_256F) {
        noxtls_slhdsa_param_t param = NOXTLS_SLHDSA_NONE;
        if(tls13_slhdsa_sig_scheme_to_param(sig_scheme, &param) == NOXTLS_RETURN_SUCCESS) {
            return noxtls_slhdsa_signature_len(param);
        }
    }
#endif
#if NOXTLS_FEATURE_ML_DSA
    switch(sig_scheme) {
        case TLS_SIGSCHEME_MLDSA44:
        case TLS_SIGSCHEME_RSA_PSS_SHA256_MLDSA44:
            return noxtls_mldsa_signature_len(NOXTLS_MLDSA_44);
        case TLS_SIGSCHEME_MLDSA65:
        case TLS_SIGSCHEME_RSA_PSS_SHA256_MLDSA65:
            return noxtls_mldsa_signature_len(NOXTLS_MLDSA_65);
        case TLS_SIGSCHEME_MLDSA87:
        case TLS_SIGSCHEME_RSA_PSS_SHA384_MLDSA87:
            return noxtls_mldsa_signature_len(NOXTLS_MLDSA_87);
        default:
            break;
    }
#endif
    switch(sig_scheme) {
        case TLS_SIGSCHEME_ED25519:
            return 64U;
        case TLS_SIGSCHEME_ED448:
            return 114u;
        case TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256:
        case TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384:
            return 160u;
        case TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256:
        case 0x0805u:
        case 0x0806u:
            return 512U;
        default:
            break;
    }
    return TLS13_CV_STACK_SIGNATURE_MAX;
}



/**
 * @brief Allocate storage for a CertificateVerify handshake message body.
 * @param out Output buffer descriptor.
 * @param sig_scheme Selected SignatureScheme.
 * @return `NOXTLS_RETURN_SUCCESS` or `NOXTLS_RETURN_NOT_ENOUGH_MEMORY`.
 */
static noxtls_return_t tls13_cv_msg_buf_init(tls13_cv_msg_buf_t *out, uint16_t sig_scheme)
{
    uint32_t sig_cap;
    uint32_t total;

    if(out == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    sig_cap = tls13_certificate_verify_signature_capacity(sig_scheme);
    total = 8U + sig_cap;
    out->buf = out->stack_storage;
    out->cap = (uint32_t)sizeof(out->stack_storage);
    if(total > out->cap) {
        out->buf = (uint8_t *)noxtls_malloc(total);
        if(out->buf == NULL) {
            out->cap = 0U;
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        out->cap = total;
    }
    memset(out->buf, 0, out->cap);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Release a CertificateVerify message buffer from tls13_cv_msg_buf_init().
 * @param buf Buffer descriptor.
 */
static void tls13_cv_msg_buf_free(tls13_cv_msg_buf_t *buf)
{
    if(buf == NULL) {
        return;
    }
    if(buf->buf != NULL && buf->buf != buf->stack_storage) {
        noxtls_free(buf->buf);
    }
    buf->buf = NULL;
    buf->cap = 0U;
}

/**
 * @brief Build the TLS 1.3 CertificateVerify to sign content
 *
 * @param[in] ctx The context to build the CertificateVerify to sign content from
 * @param[in] sig_scheme The signature scheme to use for the CertificateVerify
 * @param[in] ctx_str The context string to use for the CertificateVerify
 * @param[in] ctx_str_len The length of the context string
 * @param[out] to_sign The output buffer for the CertificateVerify to sign content
 * @param[out] to_sign_len The length of the output buffer for the CertificateVerify to sign content
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context or context string or output buffer 
 *         or output length is NULL, or NOXTLS_RETURN_INVALID_ALGORITHM if the signature scheme is invalid, or 
 *         NOXTLS_RETURN_FAILED if the CertificateVerify to sign content cannot be built
 */
static noxtls_return_t tls13_build_certificate_verify_tosign(tls13_context_t *ctx,
                                                           uint16_t sig_scheme,
                                                           const char *ctx_str,
                                                           uint32_t ctx_str_len,
                                                           uint8_t *to_sign,
                                                           uint32_t *to_sign_len)
{
    noxtls_hash_algos_t hash_algo;
    uint8_t transcript_hash[64];
    uint32_t transcript_len = sizeof(transcript_hash);
    noxtls_return_t rc;

    uint32_t hash_len;
    uint32_t key_len;

    if(ctx == NULL || ctx_str == NULL || to_sign == NULL || to_sign_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    /*
     * RFC 8446 §4.4.3: Transcript-Hash uses the negotiated cipher-suite hash.
     * When no suite is known (cipher_suite == 0), fall back to SignatureScheme hash.
     */
    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        if(!tls13_sig_scheme_certificate_verify_hash(sig_scheme, &hash_algo)) {
            return NOXTLS_RETURN_INVALID_ALGORITHM;
        }
    }
    rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                             transcript_hash, &transcript_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    memset(to_sign, 0x20, 64);
    *to_sign_len = 64;
    memcpy(to_sign + *to_sign_len, ctx_str, ctx_str_len);
    *to_sign_len += ctx_str_len;
    to_sign[(*to_sign_len)++] = 0x00;
    memcpy(to_sign + *to_sign_len, transcript_hash, transcript_len);
    *to_sign_len += transcript_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Get the transcript hash length for a signature scheme
 *
 * @param[in] signature_scheme The signature scheme to get the transcript hash length for
 * @param[out] hash_len_out The length of the transcript hash
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the hash length is NULL, or 
 *         NOXTLS_RETURN_INVALID_ALGORITHM if the signature scheme is invalid
 */
noxtls_return_t noxtls_tls13_certificate_verify_transcript_hash_length(uint16_t signature_scheme,
                                                                        uint32_t *hash_len_out)
{
    noxtls_hash_algos_t hash_algo;

    if(hash_len_out == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!tls13_sig_scheme_certificate_verify_hash(signature_scheme, &hash_algo)) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if(hash_algo == NOXTLS_HASH_SHA_256) {
        *hash_len_out = 32U;
    } else if(hash_algo == NOXTLS_HASH_SHA_384) {
        *hash_len_out = 48U;
    } else if(hash_algo == NOXTLS_HASH_SHA_512) {
        *hash_len_out = 64U;
    } else {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Build the TLS 1.3 CertificateVerify signed content
 *
 * @param[in] handshake_messages The handshake messages to build the CertificateVerify signed content from
 * @param[in] handshake_messages_len The length of the handshake messages
 * @param[in] signature_scheme The signature scheme to use for the CertificateVerify
 * @param[in] role The role to use for the CertificateVerify
 * @param[out] out The output buffer for the CertificateVerify signed content
 * @param[out] out_len The length of the output buffer for the CertificateVerify signed content
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the handshake messages or output buffer or output length is NULL, or 
 *         NOXTLS_RETURN_INVALID_PARAM if the role is invalid, or 
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY if the output buffer is too long
 */
noxtls_return_t noxtls_tls13_certificate_verify_build_signed_content(const uint8_t *handshake_messages,
                                                                     uint32_t handshake_messages_len,
                                                                     uint16_t signature_scheme,
                                                                     tls_role_t role,
                                                                     uint8_t *out,
                                                                     uint32_t *out_len)
{
    return noxtls_tls13_certificate_verify_build_signed_content_ex(handshake_messages,
                                                                   handshake_messages_len,
                                                                   signature_scheme,
                                                                   0U,
                                                                   role,
                                                                   out,
                                                                   out_len);
}

noxtls_return_t noxtls_tls13_certificate_verify_build_signed_content_ex(const uint8_t *handshake_messages,
                                                                          uint32_t handshake_messages_len,
                                                                          uint16_t signature_scheme,
                                                                          uint16_t cipher_suite,
                                                                          tls_role_t role,
                                                                          uint8_t *out,
                                                                          uint32_t *out_len)
{
    tls13_context_t ctx;
    const char *ctx_str;
    uint32_t ctx_str_len;

    if(handshake_messages == NULL || out == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(role == TLS_ROLE_SERVER) {
        ctx_str = "TLS 1.3, server CertificateVerify";
    } else if(role == TLS_ROLE_CLIENT) {
        ctx_str = "TLS 1.3, client CertificateVerify";
    } else {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    ctx_str_len = (uint32_t)strlen(ctx_str);
    memset(&ctx, 0, sizeof(ctx));
    ctx.cipher_suite = cipher_suite;
    ctx.handshake_messages = (uint8_t *)handshake_messages;
    ctx.handshake_messages_len = handshake_messages_len;
    return tls13_build_certificate_verify_tosign(&ctx, signature_scheme, ctx_str, ctx_str_len, out, out_len);
}

#if NOXTLS_FEATURE_SLH_DSA
/**
 * @brief Convert a SLHDSA parameter to a signature scheme
 *
 * @param[in] param The SLHDSA parameter to convert
 * @return The signature scheme
 */
static uint16_t tls13_slhdsa_param_to_sig_scheme(noxtls_slhdsa_param_t param)
{
    switch(param) {
        case NOXTLS_SLHDSA_SHA2_128S:
            return TLS_SIGSCHEME_SLHDSA_SHA2_128S;
        case NOXTLS_SLHDSA_SHA2_128F:
            return TLS_SIGSCHEME_SLHDSA_SHA2_128F;
        case NOXTLS_SLHDSA_SHA2_192S:
            return TLS_SIGSCHEME_SLHDSA_SHA2_192S;
        case NOXTLS_SLHDSA_SHA2_192F:
            return TLS_SIGSCHEME_SLHDSA_SHA2_192F;
        case NOXTLS_SLHDSA_SHA2_256S:
            return TLS_SIGSCHEME_SLHDSA_SHA2_256S;
        case NOXTLS_SLHDSA_SHA2_256F:
            return TLS_SIGSCHEME_SLHDSA_SHA2_256F;
        case NOXTLS_SLHDSA_SHAKE_128S:
            return TLS_SIGSCHEME_SLHDSA_SHAKE_128S;
        case NOXTLS_SLHDSA_SHAKE_128F:
            return TLS_SIGSCHEME_SLHDSA_SHAKE_128F;
        case NOXTLS_SLHDSA_SHAKE_192S:
            return TLS_SIGSCHEME_SLHDSA_SHAKE_192S;
        case NOXTLS_SLHDSA_SHAKE_192F:
            return TLS_SIGSCHEME_SLHDSA_SHAKE_192F;
        case NOXTLS_SLHDSA_SHAKE_256S:
            return TLS_SIGSCHEME_SLHDSA_SHAKE_256S;
        case NOXTLS_SLHDSA_SHAKE_256F:
            return TLS_SIGSCHEME_SLHDSA_SHAKE_256F;
        default:
            return 0U;
    }
}

/**
 * @brief Convert a signature scheme to a SLHDSA parameter
 *
 * @param[in] scheme The signature scheme to convert
 * @param[out] param The SLHDSA parameter to convert to
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the parameter is NULL, or NOXTLS_RETURN_INVALID_PARAM if the signature scheme is invalid
 */
static noxtls_return_t tls13_slhdsa_sig_scheme_to_param(uint16_t scheme, noxtls_slhdsa_param_t *param)
{
    if(param == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(scheme < TLS_SIGSCHEME_SLHDSA_SHA2_128S || scheme > TLS_SIGSCHEME_SLHDSA_SHAKE_256F) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    *param = (noxtls_slhdsa_param_t)((uint32_t)NOXTLS_SLHDSA_SHA2_128S +
                                     (uint32_t)(scheme - TLS_SIGSCHEME_SLHDSA_SHA2_128S));
    return NOXTLS_RETURN_SUCCESS;
}
#endif

/**
 * @brief Select the server certificate signature scheme
 *
 * @param[in] ctx The context to select the server certificate signature scheme from
 * @return The server certificate signature scheme
 */
static uint16_t tls13_select_server_certificate_sig_scheme(const tls13_context_t *ctx)
{
    uint32_t i;
    const tls_signature_algorithms_extension_t *sigalgs;

    if(ctx == NULL) {
        return 0;
    }

    sigalgs = ctx->client_extensions.signature_algorithms;
    if(sigalgs == NULL || sigalgs->algorithms == NULL || sigalgs->count == 0U) {
        return tls13_select_server_certificate_sig_scheme_legacy(ctx);
    }

    for(i = 0; i < sigalgs->count; i++) {
        uint16_t s = sigalgs->algorithms[i];
        if(tls13_server_can_sign_scheme(ctx, s)) {
            return s;
        }
    }
    return 0U;
}

/**
 * @brief Send a fatal alert
 *
 * @param[in] ctx The context to send the fatal alert from
 * @param[in] alert_desc The description of the fatal alert
 */
static void tls13_send_fatal_alert(tls13_context_t *ctx, uint8_t alert_desc)
{
    uint8_t alert_bytes[2];
    noxtls_return_t send_rc;

    if(ctx == NULL) {
        return;
    }
    if(ctx->peer_alert_received) {
        return;
    }

    alert_bytes[0] = TLS_ALERT_LEVEL_FATAL;
    alert_bytes[1] = alert_desc;

    /*
     * In TLS 1.3 once handshake traffic keys are active, alerts must be sent
     * encrypted as TLSInnerPlaintext(content_type=alert) inside an
     * ApplicationData record.
     */
    if(ctx->handshake_encrypted && ctx->record_workspace != NULL) {
        uint32_t inner_len = (uint32_t)(TLS_MAX_RECORD_SIZE + 32);
        uint32_t encrypted_len = (uint32_t)(TLS_MAX_RECORD_SIZE + 32);
        uint8_t *inner = ctx->record_workspace;
        uint8_t *encrypted = ctx->record_workspace + (TLS_MAX_RECORD_SIZE + 32);

        send_rc = tls13_build_inner_plaintext(alert_bytes, sizeof(alert_bytes),
                                              TLS_RECORD_ALERT, inner, &inner_len);
        if(send_rc == NOXTLS_RETURN_SUCCESS) {
            if(tls13_is_dtls(ctx)) {
                send_rc = noxtls_tls13_send_dtls13_encrypted_record(
                    ctx, 1, TLS_RECORD_ALERT, inner, inner_len, 1);
            } else {
                send_rc = noxtls_tls13_encrypt_record(ctx, TLS_RECORD_APPLICATION_DATA,
                                                      inner, inner_len,
                                                      encrypted, &encrypted_len);
                if(send_rc == NOXTLS_RETURN_SUCCESS) {
                    send_rc = noxtls_tls_send_record(&ctx->base.base,
                                                     TLS_RECORD_APPLICATION_DATA,
                                                     encrypted, encrypted_len);
                }
            }
            if(send_rc == NOXTLS_RETURN_SUCCESS) {
                return;
            }
        }
    }

    (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, alert_desc);
}

static int tls13_is_certificate_validation_error(noxtls_return_t rc)
{
    return (rc == NOXTLS_RETURN_CERT_VERIFY_FAILED ||
            rc == NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED ||
            rc == NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH ||
            rc == NOXTLS_RETURN_CERT_EXPIRED ||
            rc == NOXTLS_RETURN_CERT_NOT_YET_VALID ||
            rc == NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED ||
            rc == NOXTLS_RETURN_CERT_REVOKED ||
            rc == NOXTLS_RETURN_INVALID_ALGORITHM);
}

/**
 * @brief Send a handshake alert for an error
 *
 * @param[in] ctx The context to send the handshake alert for the error from
 * @param[in] rc The error code to send the handshake alert for
 */
static void tls13_send_handshake_alert_for_error(tls13_context_t *ctx, noxtls_return_t rc)
{
    uint8_t alert_desc = TLS_ALERT_HANDSHAKE_FAILURE;

    if(ctx == NULL) {
        return;
    }
    if(ctx->peer_alert_received) {
        return;
    }

    switch(rc) {
        case NOXTLS_RETURN_TLS_ERROR:
            alert_desc = TLS_ALERT_UNEXPECTED_MESSAGE;
            break;
        case NOXTLS_RETURN_NOT_INITIALIZED:
            alert_desc = TLS_ALERT_MISSING_EXTENSION;
            break;
        case NOXTLS_RETURN_BAD_DATA:
            alert_desc = TLS_ALERT_DECODE_ERROR;
            break;
        case NOXTLS_RETURN_RECORD_OVERFLOW:
            alert_desc = TLS_ALERT_RECORD_OVERFLOW;
            break;
        case NOXTLS_RETURN_TLS_RECORD_AUTH_FAILED:
            alert_desc = TLS_ALERT_BAD_RECORD_MAC;
            break;
        case NOXTLS_RETURN_INVALID_PARAM:
        case NOXTLS_RETURN_INVALID_ALGORITHM:
        case NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER:
            alert_desc = TLS_ALERT_ILLEGAL_PARAMETER;
            break;
        case NOXTLS_RETURN_CERT_VERIFY_FAILED:
        case NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED:
        case NOXTLS_RETURN_CERT_REVOKED:
        case NOXTLS_RETURN_CERT_EXPIRED:
        case NOXTLS_RETURN_CERT_NOT_YET_VALID:
            alert_desc = TLS_ALERT_BAD_CERTIFICATE;
            break;
        case NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED:
            alert_desc = TLS_ALERT_DECRYPT_ERROR;
            break;
        case NOXTLS_RETURN_CERT_REQUIRED:
            alert_desc = TLS_ALERT_CERTIFICATE_REQUIRED;
            break;
        default:
            break;
    }

    tls13_send_fatal_alert(ctx, alert_desc);
}

/**
 * @brief Initialize a DTLS 1.3 context (TLS 1.3 init plus DTLS version).
 * @param[in,out] ctx  Context structure to initialize.
 * @param[in] role     `TLS_ROLE_CLIENT` or `TLS_ROLE_SERVER`.
 * @return `NOXTLS_RETURN_SUCCESS` on success; error code from `noxtls_tls13_context_init` on failure.
 */
noxtls_return_t noxtls_dtls13_context_init(tls13_context_t *ctx, tls_role_t role)
{
    noxtls_return_t rc = noxtls_tls13_context_init(ctx, role);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    ctx->base.base.version = DTLS_VERSION_1_3;
    return NOXTLS_RETURN_SUCCESS;
}

static void tls13_free_client_key_shares(tls13_context_t *ctx)
{
    if(ctx == NULL || ctx->client_key_shares == NULL) {
        return;
    }

    if(ctx->client_key_shares != &ctx->client_key_share_inline) {
        for(uint32_t i = 0; i < ctx->client_key_shares_count; i++) {
            if(ctx->client_key_shares[i].key_exchange != NULL) {
                free(ctx->client_key_shares[i].key_exchange);
            }
        }
        free(ctx->client_key_shares);
    }

    memset(&ctx->client_key_share_inline, 0, sizeof(ctx->client_key_share_inline));
    memset(ctx->client_key_share_inline_buf, 0, sizeof(ctx->client_key_share_inline_buf));
    ctx->client_key_shares = NULL;
    ctx->client_key_shares_count = 0;
}

static void tls13_free_server_key_share(tls13_context_t *ctx)
{
    if(ctx == NULL || ctx->server_key_share == NULL) {
        return;
    }

    if(ctx->server_key_share != &ctx->server_key_share_inline) {
        if(ctx->server_key_share->key_exchange != NULL) {
            free(ctx->server_key_share->key_exchange);
        }
        free(ctx->server_key_share);
    }

    memset(&ctx->server_key_share_inline, 0, sizeof(ctx->server_key_share_inline));
    memset(ctx->server_key_share_inline_buf, 0, sizeof(ctx->server_key_share_inline_buf));
    ctx->server_key_share = NULL;
}

static void tls13_release_ecdhe_ctx(tls13_context_t *ctx)
{
    tls_ecdhe_context_t *ecdhe_ctx;

    if(ctx == NULL || ctx->ecdhe_ctx == NULL) {
        return;
    }

    ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
    noxtls_tls_ecdhe_context_free(ecdhe_ctx);
    if(ecdhe_ctx != &ctx->ecdhe_ctx_inline) {
        free(ecdhe_ctx);
    } else {
        memset(&ctx->ecdhe_ctx_inline, 0, sizeof(ctx->ecdhe_ctx_inline));
    }
    ctx->ecdhe_ctx = NULL;
}

noxtls_return_t noxtls_dtls13_context_init_with_workspaces(tls13_context_t *ctx,
                                                           tls_role_t role,
                                                           uint8_t *record_workspace,
                                                           uint32_t record_workspace_len,
                                                           uint8_t *handshake_workspace,
                                                           uint32_t handshake_workspace_len)
{
    noxtls_return_t rc = noxtls_tls13_context_init_with_workspaces(
        ctx,
        role,
        record_workspace,
        record_workspace_len,
        handshake_workspace,
        handshake_workspace_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    ctx->base.base.version = DTLS_VERSION_1_3;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Get the cipher parameters
 *
 * @param[in] cipher_suite The cipher suite to get the parameters from
 * @param[out] hash_algo The hash algorithm to use
 * @param[out] hash_len The length of the hash
 * @param[out] key_len The length of the key
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the hash algorithm or hash length or key length is NULL, or 
 *         NOXTLS_RETURN_INVALID_PARAM if the cipher suite is invalid, or 
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY if the hash or key is too long
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
        case TLS_CIPHER_SUITE_AES_128_CCM_SHA256:
        case TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256:
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
 * @brief Hash the messages
 *
 * @param[in] hash_algo The hash algorithm to use
 * @param[in] messages The messages to hash
 * @param[in] messages_len The length of the messages
 * @param[out] out_hash The output hash
 * @param[out] out_hash_len The length of the output hash
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the output hash or output hash length is NULL, or 
 *         NOXTLS_RETURN_INVALID_ALGORITHM if the hash algorithm is invalid, or 
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY if the output hash is too long
 */
static noxtls_return_t tls13_hash_messages(noxtls_hash_algos_t hash_algo,
                                             const uint8_t *messages, uint32_t messages_len,
                                             uint8_t *out_hash, uint32_t *out_hash_len)
{
    if(out_hash == NULL || out_hash_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t sha_ctx;
        noxtls_sha256_init(&sha_ctx, hash_algo);
        if(messages != NULL && messages_len > 0) {
            noxtls_sha256_update(&sha_ctx, (uint8_t*)messages, messages_len);
        }
        *out_hash_len = 32;
        return noxtls_sha256_finish(&sha_ctx, out_hash);
    }

    if(hash_algo == NOXTLS_HASH_SHA_384) {
        noxtls_sha512_ctx_t sha_ctx;
        noxtls_sha512_init(&sha_ctx, hash_algo);
        if(messages != NULL && messages_len > 0) {
            noxtls_sha512_update(&sha_ctx, (uint8_t*)messages, messages_len);
        }
        *out_hash_len = 48;
        return noxtls_sha512_finish(&sha_ctx, out_hash);
    }

    return NOXTLS_RETURN_INVALID_ALGORITHM;
}

/**
 * Derive 0-RTT (early data) keys on client after sending ClientHello with early_data.
 * Uses ticket_cipher_suite and resumption_psk; transcript is only ClientHello.
 */
/**
 * @brief Derive the 0-RTT (early data) keys
 *
 * @param[in] ctx The context to derive the 0-RTT (early data) keys from
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, or 
 *         NOXTLS_RETURN_FAILED if the 0-RTT (early data) keys cannot be derived, or 
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY if the 0-RTT (early data) keys are too long
 */
static noxtls_return_t tls13_derive_early_data_keys(tls13_context_t *ctx)
{
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    uint32_t prk_len;
    uint8_t early_secret_buf[64];
    noxtls_return_t rc;

    if(ctx == NULL || !ctx->ticket_stored || ctx->resumption_psk_len == 0 ||
       ctx->handshake_messages == NULL || ctx->handshake_messages_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    rc = tls13_get_cipher_params(ctx->ticket_cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    prk_len = hash_len;
    rc = noxtls_hkdf_extract(hash_algo, NULL, 0, ctx->resumption_psk, (uint32_t)ctx->resumption_psk_len,
                      early_secret_buf, &prk_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* client_early_traffic_secret = Derive-Secret(early_secret, "c e traffic", Hash(ClientHello)) */
    rc = tls13_ctx_derive_secret(ctx, hash_algo, early_secret_buf, hash_len,
                             (const uint8_t*)"c e traffic", 12,
                             ctx->handshake_messages, ctx->handshake_messages_len,
                             ctx->client_early_traffic_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->client_early_traffic_secret, hash_len,
                                 (const uint8_t*)"key", 3, NULL, 0,
                                 ctx->early_write_key, key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->client_early_traffic_secret, hash_len,
                                 (const uint8_t*)"iv", 2, NULL, 0,
                                 ctx->early_write_iv, 12);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    ctx->early_seq_num = 0;
    ctx->early_data_phase = 1;
    noxtls_debug_printf("[TLS13_DEBUG] 0-RTT keys derived (ticket_cipher=0x%04X)\n", ctx->ticket_cipher_suite);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Derive the handshake keys
 *
 * @param[in] ctx The context to derive the handshake keys from
 * @param[in] shared_secret The shared secret to derive the handshake keys from
 * @param[in] shared_secret_len The length of the shared secret
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, or 
 *         NOXTLS_RETURN_FAILED if the handshake keys cannot be derived, or 
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY if the handshake keys are too long
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

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 1U, ctx->cipher_suite);
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

    if(shared_secret != NULL && shared_secret_len > 0) {
        noxtls_debug_printf("[TLS13_DEBUG] derive_handshake_keys: shared[0..3]=%02X%02X%02X%02X len=%u\n",
                              shared_secret[0], shared_secret[1], shared_secret[2], shared_secret[3], shared_secret_len);
        noxtls_debug_printf("[TLS13_DEBUG] shared_secret=");
        for(uint32_t i = 0; i < shared_secret_len; i++) {
            noxtls_debug_printf("%02X", shared_secret[i]);
        }
        noxtls_debug_printf("\n");
    } else {
        noxtls_debug_printf("[TLS13_DEBUG] derive_handshake_keys: no ecdhe shared secret (PSK-only path)\n");
    }

    prk_len = hash_len;
    if(ctx->psk_in_use && ctx->psk_key_len > 0) {
        rc = noxtls_hkdf_extract(hash_algo, NULL, 0, ctx->psk_key, ctx->psk_key_len, ctx->early_secret, &prk_len);
    } else {
        rc = noxtls_hkdf_extract(hash_algo, NULL, 0, zero_ikm, hash_len, ctx->early_secret, &prk_len);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 2U, hash_len);
    noxtls_debug_printf("[TLS13_DEBUG] early_secret[0..3]=%02X%02X%02X%02X\n",
                          ctx->early_secret[0], ctx->early_secret[1], ctx->early_secret[2], ctx->early_secret[3]);

    /* Server: derive 0-RTT read keys only when a PSK was accepted (RFC 8446 0-RTT requires PSK). */
    if(ctx->base.base.role == TLS_ROLE_SERVER && ctx->psk_in_use && ctx->client_offered_early_data &&
       ctx->handshake_messages != NULL && ctx->handshake_messages_len >= 4) {
        uint32_t ch_len = 4U + ((uint32_t)ctx->handshake_messages[1] << 16) + ((uint32_t)ctx->handshake_messages[2] << 8) + ctx->handshake_messages[3];
        if(ch_len > ctx->handshake_messages_len) {
            ch_len = ctx->handshake_messages_len;
        }
        rc = tls13_ctx_derive_secret(ctx, hash_algo, ctx->early_secret, hash_len,
                                 (const uint8_t*)"c e traffic", 12,
                                 ctx->handshake_messages, ch_len,
                                 ctx->client_early_traffic_secret, hash_len);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->client_early_traffic_secret, hash_len,
                                         (const uint8_t*)"key", 3, NULL, 0,
                                         ctx->early_write_key, key_len);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->client_early_traffic_secret, hash_len,
                                             (const uint8_t*)"iv", 2, NULL, 0,
                                             ctx->early_write_iv, 12);
            }
            if(rc == NOXTLS_RETURN_SUCCESS) {
                ctx->early_seq_num = 0;
                noxtls_debug_printf("[TLS13_DEBUG] server 0-RTT read keys derived\n");
            }
        }
    }

    rc = tls13_ctx_derive_secret(ctx, hash_algo, ctx->early_secret, hash_len,
                             (const uint8_t*)"derived", 7, NULL, 0,
                             derived_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    noxtls_debug_printf("[TLS13_DEBUG] derived_secret[0..3]=%02X%02X%02X%02X\n",
                          derived_secret[0], derived_secret[1], derived_secret[2], derived_secret[3]);

    prk_len = hash_len;
    if(shared_secret != NULL && shared_secret_len > 0) {
        rc = noxtls_hkdf_extract(hash_algo, derived_secret, hash_len, shared_secret, shared_secret_len,
                          ctx->handshake_secret, &prk_len);
    } else {
        rc = noxtls_hkdf_extract(hash_algo, derived_secret, hash_len, zero_ikm, hash_len,
                          ctx->handshake_secret, &prk_len);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
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

    /* RFC 9147 ?4.2.3: record number encryption keys for DTLS 1.3 handshake */
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

    ctx->handshake_encrypted = 1;
    if(tls13_is_dtls(ctx)) {
        ctx->base.epoch = DTLS13_EPOCH_HANDSHAKE;
        ctx->base.write_seq_num = 0;
        ctx->base.read_seq_num = 0;
        ctx->base.replay_window.window_bitmap = 0;
        ctx->base.replay_window.last_seq = 0;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 3U, key_len);

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Derive the application secrets
 *
 * @param[in] ctx The context to derive the application secrets from
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, or 
 *         NOXTLS_RETURN_FAILED if the application secrets cannot be derived, or 
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY if the application secrets are too long
 */
static noxtls_return_t tls13_derive_application_secrets(tls13_context_t *ctx)
{
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    uint32_t prk_len;
    uint8_t derived_secret[64];
    const uint8_t zero_ikm[64] = {0};
    uint32_t app_transcript_len;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    app_transcript_len = ctx->handshake_messages_len;
    if(ctx->app_secret_transcript_len > 0 &&
       ctx->app_secret_transcript_len <= ctx->handshake_messages_len) {
        app_transcript_len = ctx->app_secret_transcript_len;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 4U, ctx->cipher_suite);

    rc = tls13_ctx_derive_secret(ctx, hash_algo, ctx->handshake_secret, hash_len,
                             (const uint8_t*)"derived", 7, NULL, 0,
                             derived_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    prk_len = hash_len;
    rc = noxtls_hkdf_extract(hash_algo, derived_secret, hash_len, zero_ikm, hash_len,
                      ctx->master_secret, &prk_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_ctx_derive_secret(ctx, hash_algo, ctx->master_secret, hash_len,
                             (const uint8_t*)"c ap traffic", 12,
                             ctx->handshake_messages, app_transcript_len,
                             ctx->client_application_traffic_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_ctx_derive_secret(ctx, hash_algo, ctx->master_secret, hash_len,
                             (const uint8_t*)"s ap traffic", 12,
                             ctx->handshake_messages, app_transcript_len,
                             ctx->server_application_traffic_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Install the application keys
 *
 * @param[in] ctx The context to install the application keys from
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, or 
 *         NOXTLS_RETURN_FAILED if the application keys cannot be installed, or 
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY if the application keys are too long
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
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 5U, key_len);

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

    /* RFC 9147 ?4.2.3: record number encryption keys for DTLS 1.3 application data */
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
    if(tls13_is_dtls(ctx)) {
        uint8_t epoch_low = (uint8_t)(DTLS13_EPOCH_APPLICATION & DTLS13_UNIFIED_EPOCH_MASK);
        ctx->base.epoch = DTLS13_EPOCH_APPLICATION;
        ctx->base.connection_epoch = DTLS13_EPOCH_APPLICATION;
        ctx->base.read_connection_epoch = DTLS13_EPOCH_APPLICATION;
        ctx->base.write_seq_num = 0;
        ctx->base.read_seq_num = 0;
        ctx->base.replay_window.window_bitmap = 0;
        ctx->base.replay_window.last_seq = 0;
        ctx->base.replay_windows[epoch_low].window_bitmap = 0;
        ctx->base.replay_windows[epoch_low].last_seq = 0;
        ctx->base.highest_recv_seq[epoch_low] = 0;
        ctx->base.highest_recv_seq_valid[epoch_low] = 0;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Install the server application write keys
 *
 * @param[in] ctx The context to install the server application write keys from
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, or 
 *         NOXTLS_RETURN_FAILED if the server application write keys cannot be installed, or 
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY if the server application write keys are too long
 */
static noxtls_return_t tls13_install_server_application_write_keys(tls13_context_t *ctx)
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
    if(tls13_is_dtls(ctx)) {
        rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->server_application_traffic_secret, hash_len,
                                     (const uint8_t*)"sn", 2, NULL, 0,
                                     ctx->server_sn_key, DTLS13_RECORD_NUMBER_ENC_LEN);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        ctx->base.connection_epoch = DTLS13_EPOCH_APPLICATION;
        ctx->base.epoch = DTLS13_EPOCH_APPLICATION;
        ctx->base.write_seq_num = 0;
    }

    /* RFC 8446: server write direction switches after server Finished. */
    ctx->server_seq_num = 0;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Install the client application read keys
 *
 * @param[in] ctx The context to install the client application read keys from
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, or 
 *         NOXTLS_RETURN_FAILED if the client application read keys cannot be installed, or 
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY if the client application read keys are too long
 */
static noxtls_return_t tls13_install_client_application_read_keys(tls13_context_t *ctx)
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
    if(tls13_is_dtls(ctx)) {
        uint8_t epoch_low = (uint8_t)(DTLS13_EPOCH_APPLICATION & DTLS13_UNIFIED_EPOCH_MASK);
        rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->client_application_traffic_secret, hash_len,
                                     (const uint8_t*)"sn", 2, NULL, 0,
                                     ctx->client_sn_key, DTLS13_RECORD_NUMBER_ENC_LEN);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        ctx->base.read_connection_epoch = DTLS13_EPOCH_APPLICATION;
        ctx->base.read_seq_num = 0;
        ctx->base.replay_windows[epoch_low].window_bitmap = 0;
        ctx->base.replay_windows[epoch_low].last_seq = 0;
        ctx->base.highest_recv_seq[epoch_low] = 0;
        ctx->base.highest_recv_seq_valid[epoch_low] = 0;
    }

    /* RFC 8446: client read direction switches after client Finished. */
    ctx->client_seq_num = 0;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Update the write traffic secret
 *
 * @param[in] ctx The context to update the write traffic secret from
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, NOXTLS_RETURN_INVALID_PARAM if the hash length is too long, or NOXTLS_RETURN_FAILED if the write traffic secret cannot be updated
 */
static noxtls_return_t tls13_update_write_traffic_secret(tls13_context_t *ctx)
{
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    noxtls_return_t rc;
    uint8_t *write_secret;
    uint8_t *write_key;
    uint8_t *write_iv;
    uint64_t *write_seq;
    uint8_t next_secret[64];

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(hash_len > sizeof(next_secret)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    write_secret = (ctx->base.base.role == TLS_ROLE_SERVER)
                     ? ctx->server_application_traffic_secret
                     : ctx->client_application_traffic_secret;

    if(ctx->base.base.role == TLS_ROLE_SERVER) {
        write_key = ctx->server_write_key;
        write_iv = ctx->server_write_iv;
        write_seq = &ctx->server_seq_num;
    } else {
        write_key = ctx->client_write_key;
        write_iv = ctx->client_write_iv;
        write_seq = &ctx->client_seq_num;
    }

    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, write_secret, hash_len,
                                 (const uint8_t *)"traffic upd", 11,
                                 NULL, 0, next_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    memcpy(write_secret, next_secret, hash_len);

    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, write_secret, hash_len,
                                 (const uint8_t *)"key", 3, NULL, 0,
                                 write_key, key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, write_secret, hash_len,
                                 (const uint8_t *)"iv", 2, NULL, 0,
                                 write_iv, 12);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(tls13_is_dtls(ctx)) {
        uint8_t *write_sn_key = (ctx->base.base.role == TLS_ROLE_SERVER) ? ctx->server_sn_key : ctx->client_sn_key;
        rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, write_secret, hash_len,
                                     (const uint8_t *)"sn", 2, NULL, 0,
                                     write_sn_key, DTLS13_RECORD_NUMBER_ENC_LEN);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(ctx->base.connection_epoch < DTLS13_EPOCH_APPLICATION) {
            ctx->base.connection_epoch = DTLS13_EPOCH_APPLICATION;
        }
        ctx->base.connection_epoch++;
        ctx->base.epoch = (uint16_t)ctx->base.connection_epoch;
        ctx->base.write_seq_num = 0;
    }
    *write_seq = 0;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Update the read traffic secret
 *
 * @param[in] ctx The context to update the read traffic secret from
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, NOXTLS_RETURN_INVALID_PARAM if the hash length is too long, or NOXTLS_RETURN_FAILED if the read traffic secret cannot be updated
 */
static noxtls_return_t tls13_update_read_traffic_secret(tls13_context_t *ctx)
{
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    noxtls_return_t rc;
    uint8_t *read_secret;
    uint8_t *read_key;
    uint8_t *read_iv;
    uint64_t *read_seq;
    uint8_t next_secret[64];

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(hash_len > sizeof(next_secret)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    read_secret = (ctx->base.base.role == TLS_ROLE_SERVER)
                    ? ctx->client_application_traffic_secret
                    : ctx->server_application_traffic_secret;

    if(ctx->base.base.role == TLS_ROLE_SERVER) {
        read_key = ctx->client_write_key;
        read_iv = ctx->client_write_iv;
        read_seq = &ctx->client_seq_num;
    } else {
        read_key = ctx->server_write_key;
        read_iv = ctx->server_write_iv;
        read_seq = &ctx->server_seq_num;
    }

    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, read_secret, hash_len,
                                 (const uint8_t *)"traffic upd", 11,
                                 NULL, 0, next_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    memcpy(read_secret, next_secret, hash_len);

    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, read_secret, hash_len,
                                 (const uint8_t *)"key", 3, NULL, 0,
                                 read_key, key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, read_secret, hash_len,
                                 (const uint8_t *)"iv", 2, NULL, 0,
                                 read_iv, 12);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(tls13_is_dtls(ctx)) {
        uint8_t *read_sn_key = (ctx->base.base.role == TLS_ROLE_SERVER) ? ctx->client_sn_key : ctx->server_sn_key;
        uint8_t epoch_low;
        rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, read_secret, hash_len,
                                     (const uint8_t *)"sn", 2, NULL, 0,
                                     read_sn_key, DTLS13_RECORD_NUMBER_ENC_LEN);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(ctx->base.read_connection_epoch < DTLS13_EPOCH_APPLICATION) {
            ctx->base.read_connection_epoch = DTLS13_EPOCH_APPLICATION;
        }
        ctx->base.read_connection_epoch++;
        ctx->base.read_seq_num = 0;
        epoch_low = (uint8_t)(ctx->base.read_connection_epoch & DTLS13_UNIFIED_EPOCH_MASK);
        ctx->base.replay_windows[epoch_low].window_bitmap = 0;
        ctx->base.replay_windows[epoch_low].last_seq = 0;
        ctx->base.highest_recv_seq[epoch_low] = 0;
        ctx->base.highest_recv_seq_valid[epoch_low] = 0;
    }
    *read_seq = 0;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generate a connection ID
 *
 * @param[out] cid The output connection ID
 * @param[in] cid_len The length of the connection ID
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_INVALID_PARAM if the connection ID is invalid, or NOXTLS_RETURN_FAILED if the connection ID cannot be generated
 */
static noxtls_return_t tls13_dtls_generate_cid(uint8_t *cid, uint8_t cid_len)
{
    drbg_state_t drbg;

    if(cid == NULL || cid_len == 0U || cid_len > 32U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(drbg_instantiate(&drbg, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(drbg_generate(&drbg, cid, (uint32_t)cid_len * 8U, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Clear the peer connection ID pool
 *
 * @param[in] ctx The context to clear the peer connection ID pool from
 */
static void tls13_dtls_peer_cid_pool_clear(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return;
    }
    memset(ctx->peer_spare_connection_ids, 0, sizeof(ctx->peer_spare_connection_ids));
    memset(ctx->peer_spare_connection_id_lens, 0, sizeof(ctx->peer_spare_connection_id_lens));
    ctx->peer_spare_connection_id_count = 0;
}

/**
 * @brief Clear the own connection ID pool
 *
 * @param[in] ctx The context to clear the own connection ID pool from
 */
static void tls13_dtls_own_cid_pool_clear(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return;
    }
    memset(ctx->own_spare_connection_ids, 0, sizeof(ctx->own_spare_connection_ids));
    memset(ctx->own_spare_connection_id_lens, 0, sizeof(ctx->own_spare_connection_id_lens));
    ctx->own_spare_connection_id_count = 0;
}

/**
 * @brief Add a connection ID to the peer connection ID pool
 *
 * @param[in] ctx The context to add the connection ID to the peer connection ID pool from
 * @param[in] cid The connection ID to add
 * @param[in] cid_len The length of the connection ID
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_INVALID_PARAM if the connection ID is invalid, or 
 *         NOXTLS_RETURN_FAILED if the connection ID cannot be added to the peer connection ID pool, or 
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY if the peer connection ID pool is full
 */
static noxtls_return_t tls13_dtls_peer_cid_pool_add(tls13_context_t *ctx, const uint8_t *cid, uint8_t cid_len)
{
    uint8_t idx;

    if(ctx == NULL || cid == NULL || cid_len == 0U || cid_len > 32U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    for(idx = 0; idx < ctx->peer_spare_connection_id_count; idx++) {
        if(ctx->peer_spare_connection_id_lens[idx] == cid_len &&
           memcmp(ctx->peer_spare_connection_ids[idx], cid, cid_len) == 0) {
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    if(ctx->peer_spare_connection_id_count >= DTLS13_MAX_CID_POOL) {
        return NOXTLS_RETURN_SUCCESS;
    }
    idx = ctx->peer_spare_connection_id_count++;
    memcpy(ctx->peer_spare_connection_ids[idx], cid, cid_len);
    ctx->peer_spare_connection_id_lens[idx] = cid_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Add a connection ID to the own connection ID pool
 *
 * @param[in] ctx The context to add the connection ID to the own connection ID pool from
 * @param[in] cid The connection ID to add
 * @param[in] cid_len The length of the connection ID
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_INVALID_PARAM if the connection ID is invalid, or 
 *         NOXTLS_RETURN_FAILED if the connection ID cannot be added to the own connection ID pool, or 
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY if the own connection ID pool is full
 */
static noxtls_return_t tls13_dtls_own_cid_pool_add(tls13_context_t *ctx, const uint8_t *cid, uint8_t cid_len)
{
    uint8_t idx;

    if(ctx == NULL || cid == NULL || cid_len == 0U || cid_len > 32U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->own_connection_id_len == 0U || cid_len != ctx->own_connection_id_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(memcmp(ctx->own_connection_id, cid, cid_len) == 0) {
        return NOXTLS_RETURN_SUCCESS;
    }
    for(idx = 0; idx < ctx->own_spare_connection_id_count; idx++) {
        if(ctx->own_spare_connection_id_lens[idx] == cid_len &&
           memcmp(ctx->own_spare_connection_ids[idx], cid, cid_len) == 0) {
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    if(ctx->own_spare_connection_id_count >= DTLS13_MAX_CID_POOL) {
        return NOXTLS_RETURN_SUCCESS;
    }
    idx = ctx->own_spare_connection_id_count++;
    memcpy(ctx->own_spare_connection_ids[idx], cid, cid_len);
    ctx->own_spare_connection_id_lens[idx] = cid_len;
    return NOXTLS_RETURN_SUCCESS;
}


/**
 * @brief Handle the request connection ID message
 *
 * @param[in] ctx The context to handle the request connection ID message from
 * @param[in] body The body of the request connection ID message
 * @param[in] body_len The length of the body of the request connection ID message
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_BAD_DATA if the request connection ID message is invalid, or 
 *         NOXTLS_RETURN_TLS_ERROR if the request connection ID message is invalid, or 
 *         NOXTLS_RETURN_FAILED if the request connection ID message cannot be handled, or 
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY if the request connection ID message is too long
 */
static noxtls_return_t tls13_handle_request_connection_id(tls13_context_t *ctx, const uint8_t *body, uint32_t body_len)
{
    uint8_t num_cids;

    if(ctx == NULL || body == NULL || body_len != 1U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(!tls13_is_dtls(ctx) || ctx->own_connection_id_len == 0U) {
        return NOXTLS_RETURN_TLS_ERROR;
    }

    num_cids = body[0];
    if(num_cids == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    return noxtls_dtls13_send_new_connection_ids(ctx, num_cids, 1U);
}

/**
 * @brief Handle the new connection ID message
 *
 * @param[in] ctx The context to handle the new connection ID message from
 * @param[in] body The body of the new connection ID message
 * @param[in] body_len The length of the body of the new connection ID message
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_BAD_DATA if the new connection ID message is invalid, or NOXTLS_RETURN_TLS_ERROR if the new connection ID message is invalid
 *         NOXTLS_RETURN_FAILED if the new connection ID message cannot be handled, or 
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY if the new connection ID message is too long
 */
static noxtls_return_t tls13_handle_new_connection_id(tls13_context_t *ctx, const uint8_t *body, uint32_t body_len)
{
    uint16_t vector_len;
    uint32_t offset = 2U;
    uint8_t cids[DTLS13_MAX_CID_POOL][32];
    uint8_t cid_lens[DTLS13_MAX_CID_POOL];
    uint8_t cid_count = 0;
    uint8_t usage;

    if(ctx == NULL || body == NULL || body_len < 3U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(!tls13_is_dtls(ctx) || ctx->peer_connection_id_len == 0U) {
        return NOXTLS_RETURN_TLS_ERROR;
    }

    vector_len = (uint16_t)(((uint16_t)body[0] << 8) | body[1]);
    if((uint32_t)vector_len + 3U != body_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    while(offset < 2U + vector_len) {
        uint8_t cid_len = body[offset++];
        if(offset + cid_len > 2U + vector_len) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(cid_len > 0U && cid_count < DTLS13_MAX_CID_POOL) {
            if(cid_len > 32U) {
                return NOXTLS_RETURN_INVALID_PARAM;
            }
            memcpy(cids[cid_count], body + offset, cid_len);
            cid_lens[cid_count] = cid_len;
            cid_count++;
        }
        offset += cid_len;
    }
    usage = body[offset];
    if(usage > 1U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(usage == 0U) {
        if(cid_count > 0U) {
            memcpy(ctx->peer_connection_id, cids[0], cid_lens[0]);
            ctx->peer_connection_id_len = cid_lens[0];
        }
        tls13_dtls_peer_cid_pool_clear(ctx);
        for(uint8_t i = 1U; i < cid_count; i++) {
            (void)tls13_dtls_peer_cid_pool_add(ctx, cids[i], cid_lens[i]);
        }
    } else {
        for(uint8_t i = 0U; i < cid_count; i++) {
            (void)tls13_dtls_peer_cid_pool_add(ctx, cids[i], cid_lens[i]);
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Handle the post-handshake message
 *
 * @param[in] ctx The context to handle the post-handshake message from
 * @param[in] msg The post-handshake message
 * @param[in] msg_len The length of the post-handshake message
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_BAD_DATA if the post-handshake message is invalid, 
 *         NOXTLS_RETURN_TLS_ERROR if the post-handshake message is invalid, or 
 *         NOXTLS_RETURN_FAILED if the post-handshake message cannot be handled, or 
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY if the post-handshake message is too long
 */
static noxtls_return_t tls13_handle_post_handshake_message(tls13_context_t *ctx, const uint8_t *msg, uint32_t msg_len)
{
    uint32_t hs_len;
    noxtls_return_t rc;

    if(ctx == NULL || msg == NULL || msg_len < 4U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    hs_len = ((uint32_t)msg[1] << 16) | ((uint32_t)msg[2] << 8) | (uint32_t)msg[3];
    /* Post-handshake messages must be exactly one complete handshake message per record boundary. */
    if(4U + hs_len != msg_len) {
        return (hs_len > msg_len) ? NOXTLS_RETURN_BAD_DATA : NOXTLS_RETURN_TLS_ERROR;
    }

    if(msg[0] == TLS_HANDSHAKE_NEW_SESSION_TICKET) {
        tls13_try_store_nst_from_handshake(ctx, msg, msg_len);
        return NOXTLS_RETURN_SUCCESS;
    }

    if(msg[0] == TLS_HANDSHAKE_REQUEST_CONNECTION_ID) {
        return tls13_handle_request_connection_id(ctx, msg + 4, hs_len);
    }

    if(msg[0] == TLS_HANDSHAKE_NEW_CONNECTION_ID) {
        return tls13_handle_new_connection_id(ctx, msg + 4, hs_len);
    }

    if(msg[0] == TLS_HANDSHAKE_KEY_UPDATE) {
        uint8_t request_update;
        if(hs_len != 1U) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        request_update = msg[4];
        if(request_update > 1U) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        rc = tls13_update_read_traffic_secret(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(request_update == 1U) {
            rc = noxtls_tls13_send_key_update(ctx, 0U);
            return rc;
        }
        return NOXTLS_RETURN_SUCCESS;
    }

    return NOXTLS_RETURN_TLS_ERROR;
}

/**
 * @brief Build the inner plaintext
 *
 * @param[in] content The content to build the inner plaintext from
 * @param[in] content_len The length of the content
 * @param[in] content_type The content type of the inner plaintext
 * @param[out] out_plaintext The output inner plaintext
 * @param[out] out_len The length of the output inner plaintext
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the output inner plaintext is NULL, 
 *         NOXTLS_RETURN_BAD_DATA if the content is invalid, or 
 *         NOXTLS_RETURN_FAILED if the inner plaintext cannot be built, or 
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY if the output inner plaintext is too long
 */
static noxtls_return_t tls13_build_inner_plaintext(const uint8_t *content, uint32_t content_len,
                                                     uint8_t content_type,
                                                     uint8_t *out_plaintext, uint32_t *out_len)
{
    if(out_plaintext == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(*out_len < content_len + 1) {
        *out_len = content_len + 1;
        return NOXTLS_RETURN_FAILED;
    }
    if(content != NULL && content_len > 0) {
        memcpy(out_plaintext, content, content_len);
    }
    out_plaintext[content_len] = content_type;
    *out_len = content_len + 1;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Extract the inner plaintext from the plaintext
 *
 * @param[in] plaintext The plaintext to extract the inner plaintext from
 * @param[in] plaintext_len The length of the plaintext
 * @param[out] content_type The content type of the inner plaintext
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the plaintext is NULL, NOXTLS_RETURN_BAD_DATA if the plaintext is invalid, or NOXTLS_RETURN_FAILED if the inner plaintext cannot be extracted
 */
static noxtls_return_t tls13_extract_inner_plaintext(const uint8_t *plaintext, uint32_t *plaintext_len, uint8_t *content_type)
{
    if(plaintext == NULL || plaintext_len == NULL || content_type == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    uint32_t len = *plaintext_len;
    while(len > 0 && plaintext[len - 1] == 0) {
        len--;
    }
    if(len == 0) {
        return NOXTLS_RETURN_TLS_ERROR;
    }
    *content_type = plaintext[len - 1];
    *plaintext_len = len - 1;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Reset the handshake buffer
 *
 * @param[in] ctx The context to reset the handshake buffer from
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
    ctx->handshake_next_at_record_boundary = 0;
}

/**
 * @brief Append data to the handshake buffer
 *
 * @param[in] ctx The context to append the data to
 * @param[in] data The data to append
 * @param[in] len The length of the data
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, NOXTLS_RETURN_BAD_DATA if the data is invalid, or NOXTLS_RETURN_FAILED if the data cannot be appended to the handshake buffer
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
    /* Track whether the next handshake noxtls_message starts at a new record boundary.
     * If we had no buffered remainder, this append begins a fresh record payload.
     * If we had remainder, this append is a continuation (cross-record fragment). */
    ctx->handshake_next_at_record_boundary = (remaining == 0) ? 1 : 0;
    return NOXTLS_RETURN_SUCCESS;
}

/* RFC 8446 ?5.1: these handshake types must not span a key change; they must be at a record boundary. */
/**
 * @brief Check if the handshake type requires a record boundary
 *
 * @param[in] msg_type The handshake type to check
 * @return 1 if the handshake type requires a record boundary, 0 otherwise
 */
static int tls13_handshake_type_requires_record_boundary(uint8_t msg_type)
{
    return (msg_type == TLS_HANDSHAKE_CLIENT_HELLO ||
            msg_type == TLS_HANDSHAKE_SERVER_HELLO ||
            msg_type == TLS_HANDSHAKE_END_OF_EARLY_DATA);
}

/**
 * @brief Get the next handshake message from the handshake buffer
 *
 * @param[in] ctx The context to get the next handshake message from
 * @param[out] out_msg The output handshake message
 * @param[out] out_len The length of the output handshake message
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, 
 *         NOXTLS_RETURN_BAD_DATA if the handshake message is invalid, or 
 *         NOXTLS_RETURN_FAILED if the handshake message cannot be retrieved, or 
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY if the output handshake message is too long
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
    /* RFC 8446 ?5.1: reject messages that must be at record boundary but were received fragmented. */
    if(tls13_handshake_type_requires_record_boundary(buf[0]) && !ctx->handshake_next_at_record_boundary) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    uint8_t *msg = (uint8_t*)malloc(total_len);
    if(msg == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(msg, buf, total_len);
    ctx->handshake_buffer_pos += total_len;
    ctx->handshake_next_at_record_boundary = 0;  /* Next noxtls_message in buffer (if any) does not start at boundary */
    if(ctx->handshake_buffer_pos >= ctx->handshake_buffer_len) {
        tls13_handshake_buffer_reset(ctx);
    }
    *out_msg = msg;
    *out_len = total_len;
    return NOXTLS_RETURN_SUCCESS;
}



/**
 * RFC 9147: DTLS 1.3 DTLSInnerPlaintext for handshake carries DTLS handshake fragments
 * (same layout as DTLS 1.2), not bare TLS 1.3 handshake messages.
 * msg is TLS wire encoding: type (1) + length (3) + body (length bytes).
 */
 /**
  * @brief Convert a TLS handshake message to a DTLS inner plaintext
  *
  * @param[in] ctx The context to convert the TLS handshake message to a DTLS inner plaintext from
  * @param[in] msg The TLS handshake message
  * @param[in] msg_len The length of the TLS handshake message
  * @param[out] inner The output DTLS inner plaintext
  * @param[in] inner_len_io The length of the output DTLS inner plaintext
  * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, 
  *         NOXTLS_RETURN_BAD_DATA if the TLS handshake message is invalid, or 
  *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY if the output DTLS inner plaintext is too long, or 
  *         NOXTLS_RETURN_FAILED if the DTLS inner plaintext cannot be converted
  */
static noxtls_return_t tls13_dtls_inner_plaintext_from_tls_handshake(tls13_context_t *ctx,
                                                                      const uint8_t *msg,
                                                                      uint32_t msg_len,
                                                                      uint8_t *inner,
                                                                      uint32_t *inner_len_io)
{
    uint32_t cap = *inner_len_io;
    uint32_t body_len;
    uint8_t msg_type;
    uint32_t max_fragment;
    uint32_t offset = 0;
    uint32_t pos = 0;
    uint16_t message_seq;

    if(msg_len < 4U) {
        return NOXTLS_RETURN_FAILED;
    }
    body_len = ((uint32_t)msg[1] << 16) | ((uint32_t)msg[2] << 8) | (uint32_t)msg[3];
    if(4U + body_len != msg_len) {
        return NOXTLS_RETURN_FAILED;
    }
    msg_type = msg[0];
    message_seq = ctx->base.send_message_seq;

    max_fragment = DTLS_MAX_FRAGMENT_SIZE;
    if(ctx->base.max_fragment > 0U) {
        max_fragment = ctx->base.max_fragment;
    }
    if(max_fragment < DTLS_MIN_FRAGMENT_SIZE) {
        max_fragment = DTLS_MIN_FRAGMENT_SIZE;
    }
    if(max_fragment > DTLS_MAX_FRAGMENT_SIZE) {
        max_fragment = DTLS_MAX_FRAGMENT_SIZE;
    }

    if(body_len == 0U) {
        if(pos + DTLS_HANDSHAKE_HEADER_SIZE + 1U > cap) {
            return NOXTLS_RETURN_FAILED;
        }
        inner[pos++] = msg_type;
        inner[pos++] = 0;
        inner[pos++] = 0;
        inner[pos++] = 0;
        inner[pos++] = (uint8_t)((message_seq >> 8) & 0xFF);
        inner[pos++] = (uint8_t)(message_seq & 0xFF);
        inner[pos++] = 0;
        inner[pos++] = 0;
        inner[pos++] = 0;
        inner[pos++] = 0;
        inner[pos++] = 0;
        inner[pos++] = 0;
    } else {
        while(offset < body_len) {
            uint32_t chunk = body_len - offset;
            if(chunk > max_fragment) {
                chunk = max_fragment;
            }
            if(pos + DTLS_HANDSHAKE_HEADER_SIZE + chunk + 1U > cap) {
                return NOXTLS_RETURN_FAILED;
            }
            inner[pos++] = msg_type;
            inner[pos++] = (uint8_t)((body_len >> 16) & 0xFF);
            inner[pos++] = (uint8_t)((body_len >> 8) & 0xFF);
            inner[pos++] = (uint8_t)(body_len & 0xFF);
            inner[pos++] = (uint8_t)((message_seq >> 8) & 0xFF);
            inner[pos++] = (uint8_t)(message_seq & 0xFF);
            inner[pos++] = (uint8_t)((offset >> 16) & 0xFF);
            inner[pos++] = (uint8_t)((offset >> 8) & 0xFF);
            inner[pos++] = (uint8_t)(offset & 0xFF);
            inner[pos++] = (uint8_t)((chunk >> 16) & 0xFF);
            inner[pos++] = (uint8_t)((chunk >> 8) & 0xFF);
            inner[pos++] = (uint8_t)(chunk & 0xFF);
            memcpy(inner + pos, msg + 4U + offset, chunk);
            pos += chunk;
            offset += chunk;
        }
    }

    inner[pos++] = TLS_RECORD_HANDSHAKE;
    *inner_len_io = pos;
    return NOXTLS_RETURN_SUCCESS;
}

#if NOXTLS_FEATURE_DTLS
/**
 * @brief Append the inner handshake fragments to the handshake buffer
 *
 * @param[in] ctx The context to append the inner handshake fragments to
 * @param[in] inner The inner handshake fragments
 * @param[in] inner_len The length of the inner handshake fragments
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, NOXTLS_RETURN_BAD_DATA if the inner handshake fragments are invalid, or NOXTLS_RETURN_FAILED if the inner handshake fragments cannot be appended to the handshake buffer
 *
 * Decrypted DTLS 1.3 handshake inner plaintext is a sequence of DTLS handshake fragments.
 * Reassemble each logical message and append TLS wire encoding (type||len||body) for tls13_handshake_buffer_get.
 */
static noxtls_return_t tls13_dtls_append_inner_handshake_fragments(tls13_context_t *ctx,
                                                                    const uint8_t *inner,
                                                                    uint32_t inner_len)
{
    dtls_context_t *dctx = &ctx->base;
    uint32_t pos = 0;

    if(ctx == NULL || (inner == NULL && inner_len > 0U)) {
        return NOXTLS_RETURN_NULL;
    }

    while(pos < inner_len) {
        dtls_handshake_fragment_t frag;
        uint8_t *complete = NULL;
        uint32_t complete_len = 0;
        noxtls_return_t rc_ass;
        uint32_t frag_len;
        uint8_t *wire;
        uint32_t wire_len;

        if(inner_len - pos < DTLS_HANDSHAKE_HEADER_SIZE) {
            return NOXTLS_RETURN_BAD_DATA;
        }

        frag.msg_type = inner[pos + DTLS_HANDSHAKE_TYPE_OFFSET];
        frag.length = ((uint32_t)inner[pos + DTLS_HANDSHAKE_LENGTH_OFFSET] << 16) |
                       ((uint32_t)inner[pos + DTLS_HANDSHAKE_LENGTH_OFFSET + 1] << 8) |
                       (uint32_t)inner[pos + DTLS_HANDSHAKE_LENGTH_OFFSET + 2];
        frag.message_seq = (uint16_t)((inner[pos + DTLS_HANDSHAKE_MESSAGE_SEQ_OFFSET] << 8) |
                                      inner[pos + DTLS_HANDSHAKE_MESSAGE_SEQ_OFFSET + 1]);
        frag.fragment_offset = ((uint32_t)inner[pos + DTLS_HANDSHAKE_FRAGMENT_OFFSET] << 16) |
                               ((uint32_t)inner[pos + DTLS_HANDSHAKE_FRAGMENT_OFFSET + 1] << 8) |
                               (uint32_t)inner[pos + DTLS_HANDSHAKE_FRAGMENT_OFFSET + 2];
        frag.fragment_length = ((uint32_t)inner[pos + DTLS_HANDSHAKE_FRAGMENT_LEN_OFFSET] << 16) |
                                ((uint32_t)inner[pos + DTLS_HANDSHAKE_FRAGMENT_LEN_OFFSET + 1] << 8) |
                                (uint32_t)inner[pos + DTLS_HANDSHAKE_FRAGMENT_LEN_OFFSET + 2];
        frag_len = frag.fragment_length;

        if(frag.msg_type < TLS_HANDSHAKE_CLIENT_HELLO || frag.msg_type > TLS_HANDSHAKE_FINISHED) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(frag.length == 0U ||
           frag.fragment_length > frag.length ||
           frag.fragment_offset + frag.fragment_length > frag.length) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(frag_len > inner_len - pos - DTLS_HANDSHAKE_HEADER_SIZE) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(inner_len - pos < DTLS_HANDSHAKE_HEADER_SIZE + frag_len) {
            return NOXTLS_RETURN_BAD_DATA;
        }

        frag.data = (uint8_t *)(inner + pos + DTLS_HANDSHAKE_BODY_OFFSET);

        rc_ass = noxtls_dtls_reassemble_handshake(dctx, &frag, &complete, &complete_len);
        if(rc_ass != NOXTLS_RETURN_SUCCESS) {
            return rc_ass;
        }

        pos += DTLS_HANDSHAKE_HEADER_SIZE + frag_len;

        if(complete != NULL) {
            wire_len = 4U + complete_len;
            wire = (uint8_t*)noxtls_malloc(wire_len);
            if(wire == NULL) {
                noxtls_free(complete);
                return NOXTLS_RETURN_FAILED;
            }
            wire[0] = frag.msg_type;
            wire[1] = (uint8_t)((complete_len >> 16) & 0xFF);
            wire[2] = (uint8_t)((complete_len >> 8) & 0xFF);
            wire[3] = (uint8_t)(complete_len & 0xFF);
            if(complete_len > 0U) {
                memcpy(wire + 4, complete, complete_len);
            }
            noxtls_free(complete);
            {
                noxtls_return_t ap = tls13_handshake_buffer_append(ctx, wire, wire_len);
                noxtls_free(wire);
                if(ap != NOXTLS_RETURN_SUCCESS) {
                    return ap;
                }
            }
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}
#endif /* NOXTLS_FEATURE_DTLS */

/**
 * @brief Send encrypted handshake
 *
 * @param[in] ctx The context to send the encrypted handshake from
 * @param[in] msg The message to send
 * @param[in] msg_len The length of the message
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, NOXTLS_RETURN_NOT_ENOUGH_MEMORY if the record workspace is not allocated, or NOXTLS_RETURN_FAILED if the encrypted handshake cannot be sent
 */
static noxtls_return_t tls13_send_encrypted_handshake(tls13_context_t *ctx, const uint8_t *msg, uint32_t msg_len)
{
    uint32_t inner_len;
    uint32_t encrypted_len;
    uint8_t *inner;
    uint8_t *encrypted;
    noxtls_return_t rc;

    if(ctx == NULL || msg == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->record_workspace == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    inner = ctx->record_workspace;
    encrypted = ctx->record_workspace + TLS13_RECORD_WORKSPACE_HALF;

    if(tls13_is_dtls(ctx)) {
        inner_len = TLS13_RECORD_WORKSPACE_HALF;
        rc = tls13_dtls_inner_plaintext_from_tls_handshake(ctx, msg, msg_len, inner, &inner_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = noxtls_tls13_send_dtls13_encrypted_record(ctx, 1, TLS_RECORD_HANDSHAKE, inner, inner_len, 1);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            ctx->base.send_message_seq++;
        }
        return rc;
    }

    {
        uint32_t offset = 0U;
        uint32_t max_fragment = TLS13_RECORD_WORKSPACE_HALF - 1U;

        while(offset < msg_len) {
            uint32_t fragment_len = msg_len - offset;
            if(fragment_len > max_fragment) {
                fragment_len = max_fragment;
            }
            inner_len = TLS13_RECORD_WORKSPACE_HALF;
            encrypted_len = TLS13_RECORD_WORKSPACE_HALF;
            rc = tls13_build_inner_plaintext(msg + offset, fragment_len, TLS_RECORD_HANDSHAKE, inner, &inner_len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }

            rc = noxtls_tls13_encrypt_record(ctx, TLS_RECORD_APPLICATION_DATA, inner, inner_len, encrypted, &encrypted_len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_APPLICATION_DATA, encrypted, encrypted_len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            offset += fragment_len;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/* RFC 8446 4.6.1: send standards-compliant NewSessionTicket. */
/**
 * @brief Send standards-compliant NewSessionTicket.
 *
 * @param[in] ctx The context to send the NewSessionTicket from
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, or NOXTLS_RETURN_FAILED if the NewSessionTicket cannot be sent
 */
static noxtls_return_t tls13_send_new_session_ticket(tls13_context_t *ctx)
{
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    uint8_t ticket_nonce[TLS13_PSK_TICKET_NONCE_MAX];
    uint8_t ticket_id[TLS13_PSK_TICKET_ID_LEN];
    uint8_t resumption_psk[64];
    uint32_t ticket_age_add;
    uint8_t *msg;
    uint32_t msg_len;
    uint32_t payload_len;
    drbg_state_t drbg_state;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(drbg_generate(&drbg_state, ticket_nonce, 16 * 8U, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(drbg_generate(&drbg_state, ticket_id, sizeof(ticket_id) * 8U, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(drbg_generate(&drbg_state, (uint8_t*)&ticket_age_add, sizeof(ticket_age_add) * 8U, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    rc = tls13_psk_derive_resumption_psk(hash_algo, (uint32_t)hash_len, ctx->master_secret,
                                         ctx->handshake_messages, ctx->handshake_messages_len,
                                         ticket_nonce, 16, resumption_psk);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls13_psk_ticket_store_add(ticket_id, TLS13_PSK_TICKET_ID_LEN, resumption_psk, (uint8_t)hash_len,
                                    ticket_nonce, 16, ticket_age_add, ctx->cipher_suite);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        memset(resumption_psk, 0, sizeof(resumption_psk));
        return rc;
    }

    /* NST payload: lifetime(4) | age_add(4) | nonce_len(1) | nonce(16) | ticket_len(2) | ticket(16) | extensions_len(2) */
    payload_len = 4 + 4 + 1 + 16 + 2 + 16 + 2;
    msg_len = 4 + payload_len;
    msg = (uint8_t*)malloc(msg_len);
    if(msg == NULL) {
        memset(resumption_psk, 0, sizeof(resumption_psk));
        return NOXTLS_RETURN_FAILED;
    }
    msg[0] = TLS_HANDSHAKE_NEW_SESSION_TICKET;
    msg[1] = (uint8_t)(payload_len >> 16);
    msg[2] = (uint8_t)(payload_len >> 8);
    msg[3] = (uint8_t)payload_len;
    /* ticket_lifetime: 86400 seconds (1 day) */
    msg[4] = 0;
    msg[5] = 0;
    msg[6] = (uint8_t)(86400 >> 8);
    msg[7] = (uint8_t)86400;
    msg[8] = (uint8_t)(ticket_age_add >> 24);
    msg[9] = (uint8_t)(ticket_age_add >> 16);
    msg[10] = (uint8_t)(ticket_age_add >> 8);
    msg[11] = (uint8_t)ticket_age_add;
    msg[12] = 16;
    memcpy(msg + 13, ticket_nonce, 16);
    msg[29] = 0;
    msg[30] = 16;
    memcpy(msg + 31, ticket_id, 16);
    /* No per-ticket extensions for now. */
    msg[47] = 0;
    msg[48] = 0;

    rc = tls13_send_encrypted_handshake(ctx, msg, msg_len);
    memset(resumption_psk, 0, sizeof(resumption_psk));
    free(msg);
    return rc;
}

/**
 * @brief Try to store the NST from the handshake
 *
 * @param[in] ctx The context to try to store the NST from
 * @param[in] decrypted The decrypted handshake message
 * @param[in] decrypted_len The length of the decrypted handshake message
 */
static void tls13_try_store_nst_from_handshake(tls13_context_t *ctx, const uint8_t *decrypted, uint32_t decrypted_len)
{
    noxtls_return_t rc;
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    const uint8_t *payload;
    uint32_t payload_len;
    uint32_t off;
    uint8_t nonce_len;
    uint16_t ticket_len;

    if(ctx == NULL || decrypted == NULL || decrypted_len < 4) {
        return;
    }
    if(decrypted[0] != TLS_HANDSHAKE_NEW_SESSION_TICKET) {
        return;
    }
    payload_len = ((uint32_t)decrypted[1] << 16) | ((uint32_t)decrypted[2] << 8) | decrypted[3];
    payload = decrypted + 4;
    if(payload_len < 13 || (uint32_t)4 + payload_len > decrypted_len) {
        return;
    }
    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return;
    }
    off = 9;
    nonce_len = payload[8];
    if(nonce_len > 32 || off + nonce_len + 2 > payload_len) {
        return;
    }
    off += nonce_len;
    ticket_len = ((uint16_t)payload[off] << 8) | payload[off + 1];
    off += 2;
    if(ticket_len > 32 || off + ticket_len + 2U > payload_len) {
        return;
    }
    ctx->ticket_age_add = ((uint32_t)payload[4] << 24) | ((uint32_t)payload[5] << 16) |
                         ((uint32_t)payload[6] << 8) | payload[7];
    memcpy(ctx->ticket_nonce, payload + 9, (size_t)nonce_len);
    ctx->ticket_nonce_len = nonce_len;
    memcpy(ctx->ticket_identity, payload + 9 + nonce_len + 2, (size_t)ticket_len);
    ctx->ticket_identity_len = ticket_len;
    off += ticket_len;
    {
        uint16_t ext_len = ((uint16_t)payload[off] << 8) | payload[off + 1];
        off += 2U;
        if(off + ext_len > payload_len) {
            return;
        }
    }
    if(hash_len > sizeof(ctx->resumption_psk)) {
        return;
    }
    memset(ctx->resumption_psk, 0, sizeof(ctx->resumption_psk));
    rc = tls13_psk_derive_resumption_psk(hash_algo, hash_len, ctx->master_secret,
                                         ctx->handshake_messages, ctx->handshake_messages_len,
                                         ctx->ticket_nonce, ctx->ticket_nonce_len,
                                         ctx->resumption_psk);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return;
    }
    ctx->resumption_psk_len = (uint8_t)hash_len;
    ctx->ticket_cipher_suite = ctx->cipher_suite;
    ctx->ticket_stored = 1;
}

/**
 * @brief Client: optionally receive one record after connect; if NST, parse and store ticket; if app data, buffer for noxtls_tls13_recv
 *
 * @param[in] ctx The context to try to receive the NST from
 */
static NOXTLS_UNUSED_ATTR void tls13_try_recv_nst(tls13_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    uint32_t decrypted_len = TLS13_RECORD_WORKSPACE_HALF;
    uint8_t *decrypted;
    uint8_t content_type = 0;

    if(ctx == NULL || ctx->base.base.role != TLS_ROLE_CLIENT) {
        return;
    }
    if(ctx->record_workspace == NULL) {
        return;
    }
    decrypted = ctx->record_workspace;  /* Reuse first half of workspace */
    memset(&record, 0, sizeof(record));
    rc = noxtls_tls_recv_record(&ctx->base.base, &record);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(record.data);
        return;
    }
    if(record.length > 0 && record.data == NULL) {
        return;
    }
    if(record.type != TLS_RECORD_APPLICATION_DATA) {
        free(record.data);
        return;
    }
    rc = noxtls_tls13_decrypt_record(ctx, record.data, record.length, decrypted, &decrypted_len);
    free(record.data);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return;
    }
    rc = tls13_extract_inner_plaintext(decrypted, &decrypted_len, &content_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return;
    }
    if(content_type == TLS_RECORD_APPLICATION_DATA) {
        if(decrypted_len > 0) {
            ctx->pending_app_data = (uint8_t*)malloc(decrypted_len);
            if(ctx->pending_app_data != NULL) {
                memcpy(ctx->pending_app_data, decrypted, decrypted_len);
                ctx->pending_app_data_len = decrypted_len;
            }
        }
        return;
    }
    if(content_type == TLS_RECORD_HANDSHAKE) {
        tls13_try_store_nst_from_handshake(ctx, decrypted, decrypted_len);
    }
}

/**
 * Receive one TLS 1.3 handshake noxtls_message (RFC 8446).
 * - Coalescing: multiple handshake messages in one record are buffered; we return one noxtls_message per call.
 * - Fragmentation: one noxtls_message spanning multiple records is reassembled by appending until we have 4 + length bytes.
 * - Order: callers (recv_encrypted_extensions, recv_certificate_request, etc.) enforce required noxtls_message order by type.
 */
static noxtls_return_t tls13_recv_handshake_message(tls13_context_t *ctx, uint8_t **out_msg, uint32_t *out_len)
{
    tls_record_t record;
    noxtls_return_t rc;
    uint8_t content_type = 0;

    if(ctx == NULL || out_msg == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(ctx->pending_handshake_msg != NULL && ctx->pending_handshake_len > 0) {
        *out_msg = ctx->pending_handshake_msg;
        *out_len = ctx->pending_handshake_len;
        ctx->pending_handshake_msg = NULL;
        ctx->pending_handshake_len = 0;
        return NOXTLS_RETURN_SUCCESS;
    }

    /* Try to satisfy from buffered data first */
    while(1) {
        rc = tls13_handshake_buffer_get(ctx, out_msg, out_len);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            if(tls13_is_ack_message(*out_msg, *out_len)) {
                tls13_dtls_handle_ack(ctx, *out_msg, *out_len);
                free(*out_msg);
                *out_msg = NULL;
                *out_len = 0;
                continue;
            }
            return rc;
        }
        if(rc == NOXTLS_RETURN_BAD_DATA) {
            return rc;
        }
        break;
    }

    while(1) {
        rc = noxtls_tls_recv_record(&ctx->base.base, &record);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_debug_printf("[TLS13_DEBUG] recv_handshake_message: recv_record rc=%d\n", rc);
            return rc;
        }
        if(record.length > 0 && record.data == NULL) {
            noxtls_debug_printf("[TLS13_DEBUG] recv_handshake_message: record.length=%u with NULL data\n", record.length);
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_debug_printf("[TLS13_DEBUG] recv_handshake_message: record.type=0x%02X len=%u handshake_encrypted=%u\n",
                            record.type, record.length, ctx->handshake_encrypted);

        if(record.type == TLS_RECORD_CHANGE_CIPHER_SPEC) {
            noxtls_return_t ccs_rc = tls13_handle_peer_compat_ccs(ctx, &record);
            free(record.data);
            if(ccs_rc != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_TLS_ERROR;
            }
            /* Valid single compatibility CCS; ignore it. */
            continue;
        }
        if(record.type == TLS_RECORD_ALERT) {
            free(record.data);
            ctx->peer_alert_received = 1;
            ctx->base.base.state = TLS_STATE_CLOSED;
            return NOXTLS_RETURN_FAILED;
        }

        /* RFC 9147: ACK can be received as record content type 26 in DTLS 1.3 */
        if(record.type == TLS_RECORD_ACK && tls13_is_dtls(ctx)) {
            if(record.length > 0 && record.data != NULL) {
                tls13_dtls_handle_ack(ctx, record.data, record.length);
            }
            free(record.data);
            continue;
        }

        /* RFC 9147: DTLSCiphertext (unified header, first byte 0x20-0x3F); support multiple records per datagram */
        if(tls13_is_dtls(ctx) && record.type >= 0x20 && record.type <= 0x3F) {
            uint32_t offset = 0;
            if(record.data == NULL) {
                return NOXTLS_RETURN_BAD_DATA;
            }
            uint32_t total_len = (uint32_t)record.length;
            while(offset < total_len) {
                uint32_t rec_size = noxtls_tls13_dtls13_record_size(record.data + offset, total_len - offset,
                                                                     ctx->own_connection_id_len);
                if(rec_size == 0) {
                    free(record.data);
                    return NOXTLS_RETURN_BAD_DATA;
                }
                {
                    uint8_t inner_type;
                    uint32_t inner_len = rec_size;
                    uint8_t *inner_buf = (uint8_t*)malloc(inner_len);
                    if(inner_buf == NULL) {
                        free(record.data);
                        return NOXTLS_RETURN_FAILED;
                    }
                    rc = noxtls_tls13_decrypt_dtls13_record(ctx, record.data + offset, rec_size,
                                                            &inner_type, inner_buf, &inner_len);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        noxtls_debug_printf("[TLS13_DEBUG] recv_handshake_message: decrypt_dtls13_record rc=%d rec_size=%u offset=%u\n",
                                            rc, rec_size, offset);
                        free(inner_buf);
                        if(rc == NOXTLS_RETURN_FAILED && tls13_dtls_resend_retained_final_ack(ctx) == NOXTLS_RETURN_SUCCESS) {
                            offset += rec_size;
                            continue;
                        }
                        free(record.data);
                        return rc;
                    }
                    if(inner_type == TLS_RECORD_HANDSHAKE) {
                        noxtls_debug_printf("[TLS13_DEBUG] recv_handshake_message: decrypted inner handshake len=%u\n", inner_len);
                        if(inner_len == 0U) {
                            free(inner_buf);
                            free(record.data);
                            tls13_send_fatal_alert(ctx, TLS_ALERT_UNEXPECTED_MESSAGE);
                            ctx->base.base.state = TLS_STATE_CLOSED;
                            return NOXTLS_RETURN_TLS_ERROR;
                        }
                        if(inner_len >= 1U && inner_buf[0] == TLS_HANDSHAKE_KEY_UPDATE) {
                            free(inner_buf);
                            free(record.data);
                            tls13_send_fatal_alert(ctx, TLS_ALERT_UNEXPECTED_MESSAGE);
                            ctx->base.base.state = TLS_STATE_CLOSED;
                            return NOXTLS_RETURN_TLS_ERROR;
                        }
#if NOXTLS_FEATURE_DTLS
                        rc = tls13_dtls_append_inner_handshake_fragments(ctx, inner_buf, inner_len);
#else
                        rc = NOXTLS_RETURN_FAILED;
#endif
                        free(inner_buf);
                        if(rc != NOXTLS_RETURN_SUCCESS) {
                            free(record.data);
                            return rc;
                        }
                        rc = tls13_handshake_buffer_get(ctx, out_msg, out_len);
                        if(rc == NOXTLS_RETURN_SUCCESS) {
                            if(tls13_is_ack_message(*out_msg, *out_len)) {
                                tls13_dtls_handle_ack(ctx, *out_msg, *out_len);
                                free(*out_msg);
                                *out_msg = NULL;
                                *out_len = 0;
                                offset += rec_size;
                                continue;
                            }
                            noxtls_debug_printf("[TLS13_DEBUG] recv_handshake_message: returning hs msg type=0x%02X len=%u\n",
                                                (*out_len > 0U && *out_msg != NULL) ? (*out_msg)[0] : 0U,
                                                *out_len);
                            free(record.data);
                            return rc;
                        }
                        if(rc == NOXTLS_RETURN_BAD_DATA) {
                            noxtls_debug_printf("[TLS13_DEBUG] recv_handshake_message: handshake_buffer_get bad data after decrypt\n");
                            free(record.data);
                            return rc;
                        }
                    } else if(inner_type == TLS_RECORD_APPLICATION_DATA) {
                        noxtls_debug_printf("[TLS13_DEBUG] recv_handshake_message: decrypted inner app-data len=%u\n", inner_len);
                        free(record.data);
                        *out_msg = inner_buf;
                        *out_len = inner_len;
                        return NOXTLS_RETURN_SUCCESS;
                    } else {
                        free(inner_buf);
                    }
                }
                offset += rec_size;
            }
            free(record.data);
            continue;
        }

        if(record.type == TLS_RECORD_HANDSHAKE && tls13_is_dtls(ctx)) {
            dtls_context_t *dctx = &ctx->base;
            if(record.length > 0 && record.data[0] == TLS_HANDSHAKE_ACK) {
                dctx->ack_pending = 0;
                dctx->ack_range_valid = 0;
                dctx->ack_range_count = 0;
            } else if(dctx->ack_pending) {
                rc = tls13_dtls_flush_ack(ctx, 0U);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    free(record.data);
                    return rc;
                }
            }
        }

        if(record.type == TLS_RECORD_HANDSHAKE) {
            /*
             * RFC 8446: after ServerHello, handshake messages are carried in
             * encrypted TLSInnerPlaintext inside ApplicationData records.
             * A plaintext handshake record at this stage is unexpected.
             */
            if(ctx->handshake_encrypted) {
                free(record.data);
                return NOXTLS_RETURN_TLS_ERROR;
            }
            /* Append and return a single handshake noxtls_message */
            rc = tls13_handshake_buffer_append(ctx, record.data, record.length);
            free(record.data);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            rc = tls13_handshake_buffer_get(ctx, out_msg, out_len);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                if(tls13_is_ack_message(*out_msg, *out_len)) {
                    tls13_dtls_handle_ack(ctx, *out_msg, *out_len);
                    free(*out_msg);
                    *out_msg = NULL;
                    *out_len = 0;
                    continue;
                }
                return rc;
            }
            if(rc == NOXTLS_RETURN_BAD_DATA) {
                return rc;
            }
            continue;
        }

        if(record.type == TLS_RECORD_APPLICATION_DATA) {
            uint8_t *decrypted = (uint8_t*)malloc(record.length);
            uint32_t decrypted_len = record.length;
            uint32_t inner_plaintext_len;
            if(decrypted == NULL) {
                free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            rc = noxtls_tls13_decrypt_record(ctx, record.data, record.length, decrypted, &decrypted_len);
            /* Server: if handshake decrypt failed, try 0-RTT decrypt only when a PSK was accepted. */
            if(rc != NOXTLS_RETURN_SUCCESS && ctx->base.base.role == TLS_ROLE_SERVER &&
               ctx->psk_in_use && ctx->client_offered_early_data && !ctx->end_of_early_data_seen) {
                decrypted_len = record.length;
                rc = noxtls_tls13_decrypt_record_early(ctx, ctx->cipher_suite, record.data, record.length,
                                                      decrypted, &decrypted_len);
            }
            free(record.data);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_debug_printf("[TLS13_DEBUG] recv_handshake: decrypt rc=%d len=%u\n", rc, decrypted_len);
                free(decrypted);
                if(rc == NOXTLS_RETURN_RECORD_OVERFLOW) {
                    return rc;
                }
                /*
                 * Client may send fake 0-RTT ciphertext with early_data + invalid PSK (binder mismatch).
                 * We reject the PSK but continue with ECDHE; discard those records while we have not yet
                 * accepted any decrypted handshake bytes for the current message (RFC: skip rejected 0-RTT).
                 * If a handshake fragment is already buffered (e.g. split Finished), a later decrypt failure
                 * must not be dropped ��� tlsfuzzer expects fatal bad_record_mac.
                 * After HelloRetryRequest, the first-flight early data is drained before the second ClientHello,
                 * so decrypt failures on the client's post-server Finished flight must not be skipped (avoids
                 * hanging when the client sends only a bogus record, e.g. tlsfuzzer "early data after 2nd CH").
                 */
                if(rc == NOXTLS_RETURN_BAD_DATA &&
                   ctx->base.base.role == TLS_ROLE_SERVER &&
                   !ctx->psk_in_use && ctx->client_offered_early_data && !ctx->end_of_early_data_seen &&
                   !ctx->sent_hrr) {
                    uint32_t hs_pending = 0U;
                    if(ctx->handshake_buffer_len >= ctx->handshake_buffer_pos) {
                        hs_pending = ctx->handshake_buffer_len - ctx->handshake_buffer_pos;
                    }
                    if(hs_pending == 0U) {
                        continue;
                    }
                }
                if(rc == NOXTLS_RETURN_BAD_DATA) {
                    return NOXTLS_RETURN_TLS_RECORD_AUTH_FAILED;
                }
                return NOXTLS_RETURN_TLS_ERROR;
            }
            inner_plaintext_len = decrypted_len;
            if(inner_plaintext_len > (uint32_t)(TLS_MAX_RECORD_SIZE + 1U)) {
                free(decrypted);
                return NOXTLS_RETURN_RECORD_OVERFLOW;
            }
            rc = tls13_extract_inner_plaintext(decrypted, &decrypted_len, &content_type);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                free(decrypted);
                if(rc == NOXTLS_RETURN_BAD_DATA) {
                    return NOXTLS_RETURN_TLS_ERROR;
                }
                return rc;
            }
            if((content_type == TLS_RECORD_HANDSHAKE || content_type == TLS_RECORD_ALERT) && decrypted_len == 0U) {
                free(decrypted);
                tls13_send_fatal_alert(ctx, TLS_ALERT_UNEXPECTED_MESSAGE);
                ctx->base.base.state = TLS_STATE_CLOSED;
                return NOXTLS_RETURN_TLS_ERROR;
            }
            /* Server: only allow 0-RTT app data during handshake when early_data was offered. */
            if(content_type == TLS_RECORD_APPLICATION_DATA &&
               ctx->base.base.role == TLS_ROLE_SERVER &&
               ctx->client_offered_early_data && !ctx->end_of_early_data_seen) {
                if(decrypted_len > 0) {
                    if(ctx->pending_app_data) free(ctx->pending_app_data);
                    ctx->pending_app_data = (uint8_t*)malloc(decrypted_len);
                    if(ctx->pending_app_data) {
                        memcpy(ctx->pending_app_data, decrypted, decrypted_len);
                        ctx->pending_app_data_len = decrypted_len;
                    }
                }
                free(decrypted);
                continue;
            }
            if(content_type == TLS_RECORD_ALERT) {
                if(decrypted_len < 2U) {
                    free(decrypted);
                    tls13_send_fatal_alert(ctx, TLS_ALERT_UNEXPECTED_MESSAGE);
                    ctx->peer_alert_received = 1;
                    ctx->base.base.state = TLS_STATE_CLOSED;
                    return NOXTLS_RETURN_FAILED;
                }
                free(decrypted);
                ctx->peer_alert_received = 1;
                ctx->base.base.state = TLS_STATE_CLOSED;
                return NOXTLS_RETURN_FAILED;
            }
            if(content_type != TLS_RECORD_HANDSHAKE) {
                noxtls_debug_printf("[TLS13_DEBUG] recv_handshake: inner type=%u len=%u\n", content_type, decrypted_len);
                free(decrypted);
                return NOXTLS_RETURN_TLS_ERROR;
            }
            if(decrypted_len >= 1U && decrypted[0] == TLS_HANDSHAKE_KEY_UPDATE) {
                free(decrypted);
                tls13_send_fatal_alert(ctx, TLS_ALERT_UNEXPECTED_MESSAGE);
                ctx->base.base.state = TLS_STATE_CLOSED;
                return NOXTLS_RETURN_TLS_ERROR;
            }
            /* EndOfEarlyData is handshake type 5 */
            if(decrypted_len >= 1 && decrypted[0] == TLS_HANDSHAKE_END_OF_EARLY_DATA) {
                if(ctx->base.base.role == TLS_ROLE_CLIENT) {
                    free(decrypted);
                    tls13_send_fatal_alert(ctx, TLS_ALERT_UNEXPECTED_MESSAGE);
                    ctx->base.base.state = TLS_STATE_CLOSED;
                    return NOXTLS_RETURN_TLS_ERROR;
                }
                ctx->end_of_early_data_seen = 1;
            }
            if(tls13_is_dtls(ctx)) {
                dtls_context_t *dctx = &ctx->base;
                tls13_dtls_ack_range_add(dctx, (uint16_t)dctx->epoch, dctx->read_seq_num);
                dctx->ack_pending = 1;
            }
            rc = tls13_handshake_buffer_append(ctx, decrypted, decrypted_len);
            free(decrypted);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            rc = tls13_handshake_buffer_get(ctx, out_msg, out_len);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                if(tls13_is_ack_message(*out_msg, *out_len)) {
                    tls13_dtls_handle_ack(ctx, *out_msg, *out_len);
                    free(*out_msg);
                    *out_msg = NULL;
                    *out_len = 0;
                    continue;
                }
                return rc;
            }
            if(rc == NOXTLS_RETURN_BAD_DATA) {
                return rc;
            }
            continue;
        }

        free(record.data);
        return NOXTLS_RETURN_TLS_ERROR;
    }
}

/**
 * @brief Initialize a TLS 1.3 context for client or server role.
 * @param[in,out] ctx  Context structure to zero and initialize.
 * @param[in] role     `TLS_ROLE_CLIENT` or `TLS_ROLE_SERVER`.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p ctx is NULL;
 *         `NOXTLS_RETURN_FAILED` or `NOXTLS_RETURN_NOT_ENOUGH_MEMORY` on setup failure.
 */
static noxtls_return_t tls13_context_init_internal(tls13_context_t *ctx,
                                                   tls_role_t role,
                                                   uint8_t *record_workspace,
                                                   uint32_t record_workspace_len,
                                                   uint8_t *handshake_workspace,
                                                   uint32_t handshake_workspace_len)
{
    int use_caller_workspaces;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    use_caller_workspaces = ((record_workspace != NULL) || (handshake_workspace != NULL)) ? 1 : 0;
    if(use_caller_workspaces &&
       (record_workspace == NULL || handshake_workspace == NULL)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(use_caller_workspaces &&
       (record_workspace_len < (uint32_t)TLS13_RECORD_WORKSPACE_SIZE ||
        handshake_workspace_len < TLS_HANDSHAKE_WORKSPACE_SIZE)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    
    /* TLS 1.3 uses 0x0303 in the record layer */
    if(noxtls_dtls_context_init(&ctx->base, role, TLS_VERSION_1_2) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    
    memset(ctx->client_random, 0, sizeof(ctx->client_random));
    memset(ctx->server_random, 0, sizeof(ctx->server_random));
    memset(ctx->client_legacy_session_id, 0, sizeof(ctx->client_legacy_session_id));
    ctx->client_legacy_session_id_len = 0;
    ctx->cipher_suite = 0;
    memset(ctx->early_secret, 0, sizeof(ctx->early_secret));
    memset(ctx->handshake_secret, 0, sizeof(ctx->handshake_secret));
    memset(ctx->master_secret, 0, sizeof(ctx->master_secret));
    ctx->client_seq_num = 0;
    ctx->server_seq_num = 0;
    ctx->server_cert = NULL;
    ctx->server_cert_len = 0;
    ctx->server_cert_chain = NULL;
    ctx->server_cert_chain_len = NULL;
    ctx->server_cert_chain_count = 0;
    ctx->server_cert_parsed = NULL;
    ctx->handshake_messages = NULL;
    ctx->handshake_messages_len = 0;
    ctx->client_tls12_downgrade_server_hello = NULL;
    ctx->client_tls12_downgrade_server_hello_len = 0;
    ctx->app_secret_transcript_len = 0;
    ctx->handshake_buffer = NULL;
    ctx->handshake_buffer_len = 0;
    ctx->handshake_buffer_pos = 0;
    ctx->handshake_encrypted = 0;
    ctx->awaiting_hrr_client_hello = 0;
    ctx->sent_hrr = 0;
    ctx->received_hrr = 0;
    ctx->hrr_first_clienthello_ext_order = NULL;
    ctx->hrr_first_clienthello_ext_order_count = 0;
    ctx->handshake_next_at_record_boundary = 0;
    ctx->client_handshake_step = TLS13_CLIENT_HS_STEP_NONE;
    ctx->server_handshake_step = 0;
    ctx->client_key_shares = NULL;
    ctx->client_key_shares_count = 0;
    ctx->server_key_share = NULL;
    ctx->ecdhe_ctx = NULL;
    ctx->selected_kex_group = 0;
    ctx->selected_kex_is_hybrid = 0;
    ctx->selected_mlkem_param = NOXTLS_MLKEM_NONE;
    ctx->mlkem_client_public_key_len = 0;
    ctx->mlkem_client_secret_key_len = 0;
    ctx->mlkem_server_public_key_len = 0;
    ctx->mlkem_server_secret_key_len = 0;
    memset(ctx->mlkem_client_public_key, 0, sizeof(ctx->mlkem_client_public_key));
    memset(ctx->mlkem_client_secret_key, 0, sizeof(ctx->mlkem_client_secret_key));
    memset(ctx->mlkem_server_public_key, 0, sizeof(ctx->mlkem_server_public_key));
    memset(ctx->mlkem_server_secret_key, 0, sizeof(ctx->mlkem_server_secret_key));
    memset(ctx->hybrid_shared_secret, 0, sizeof(ctx->hybrid_shared_secret));
    ctx->hybrid_shared_secret_len = 0;
    ctx->server_name = NULL;
    ctx->server_name_len = 0;
    ctx->server_expect_client_sni = NULL;
    ctx->server_expect_sni_fatal = 0;
    memset(&ctx->last_accept_timing, 0, sizeof(ctx->last_accept_timing));
    ctx->server_private_rsa = NULL;
    ctx->server_private_ecdsa = NULL;
    ctx->server_ecdsa_matrix_count = 0U;
    memset(ctx->server_ecdsa_matrix_certs, 0, sizeof(ctx->server_ecdsa_matrix_certs));
    memset(ctx->server_ecdsa_matrix_cert_lens, 0, sizeof(ctx->server_ecdsa_matrix_cert_lens));
    memset(ctx->server_ecdsa_matrix_keys, 0, sizeof(ctx->server_ecdsa_matrix_keys));
    memset(ctx->server_private_ed25519, 0, sizeof(ctx->server_private_ed25519));
    ctx->server_cert_use_ed25519 = 0;
    memset(ctx->server_private_ed448, 0, sizeof(ctx->server_private_ed448));
    ctx->server_cert_use_ed448 = 0;
    memset(ctx->server_private_mldsa, 0, sizeof(ctx->server_private_mldsa));
    ctx->server_private_mldsa_len = 0;
    ctx->server_private_mldsa_param = NOXTLS_MLDSA_NONE;
    ctx->server_cert_use_mldsa = 0;
    memset(ctx->server_private_slhdsa, 0, sizeof(ctx->server_private_slhdsa));
    ctx->server_private_slhdsa_len = 0;
    ctx->server_private_slhdsa_param = NOXTLS_SLHDSA_NONE;
    ctx->server_cert_use_slhdsa = 0;
    ctx->crypto_provider = NULL;
    ctx->server_private_key_handle = NULL;
    ctx->request_client_auth = 0;
    ctx->require_client_auth = 0;
    ctx->client_auth_requested = 0;
    ctx->cert_request_context_len = 0;
    ctx->client_cert = NULL;
    ctx->client_cert_len = 0;
    ctx->client_cert_parsed = NULL;
    ctx->client_private_rsa = NULL;
    ctx->client_private_ecdsa = NULL;
    memset(ctx->client_private_ed25519, 0, sizeof(ctx->client_private_ed25519));
    ctx->client_cert_use_ed25519 = 0;
    memset(ctx->client_private_ed448, 0, sizeof(ctx->client_private_ed448));
    ctx->client_cert_use_ed448 = 0;
    memset(ctx->client_private_mldsa, 0, sizeof(ctx->client_private_mldsa));
    ctx->client_private_mldsa_len = 0;
    ctx->client_private_mldsa_param = NOXTLS_MLDSA_NONE;
    ctx->client_cert_use_mldsa = 0;
    memset(ctx->client_private_slhdsa, 0, sizeof(ctx->client_private_slhdsa));
    ctx->client_private_slhdsa_len = 0;
    ctx->client_private_slhdsa_param = NOXTLS_SLHDSA_NONE;
    ctx->client_cert_use_slhdsa = 0;
    ctx->client_private_key_handle = NULL;
    ctx->prefer_chacha20 = 0;
    ctx->server_cipher_suites = NULL;
    ctx->server_cipher_suites_count = 0;
    ctx->client_supported_groups = NULL;
    ctx->client_supported_groups_count = 0;
    ctx->client_signature_algorithms = NULL;
    ctx->client_signature_algorithms_count = 0;
    ctx->server_alpn_protocols = NULL;
    ctx->server_alpn_count = 0;
    ctx->negotiated_alpn_len = 0;
    memset(ctx->negotiated_alpn, 0, sizeof(ctx->negotiated_alpn));
    memset(ctx->psk_identity, 0, sizeof(ctx->psk_identity));
    ctx->psk_identity_len = 0;
    memset(ctx->psk_key, 0, sizeof(ctx->psk_key));
    ctx->psk_key_len = 0;
    ctx->psk_configured = 0;
    ctx->psk_preferred_mode = TLS13_PSK_KE_MODE_PSK_DHE_KE;
    ctx->psk_in_use = 0;
    ctx->psk_use_ecdhe = 0;
    ctx->psk_selected_identity = 0;

    ctx->ticket_identity_len = 0;
    ctx->ticket_nonce_len = 0;
    ctx->resumption_psk_len = 0;
    ctx->ticket_age_add = 0;
    ctx->ticket_cipher_suite = 0;
    ctx->ticket_stored = 0;
    ctx->ffdhe_shared_secret_len = 0;
    ctx->pending_app_data = NULL;
    ctx->pending_app_data_len = 0;
    ctx->peer_alert_received = 0;
    ctx->pending_handshake_msg = NULL;
    ctx->pending_handshake_len = 0;
    memset(ctx->ticket_identity, 0, sizeof(ctx->ticket_identity));
    memset(ctx->ticket_nonce, 0, sizeof(ctx->ticket_nonce));
    memset(ctx->resumption_psk, 0, sizeof(ctx->resumption_psk));
    memset(ctx->ffdhe_shared_secret, 0, sizeof(ctx->ffdhe_shared_secret));
    ctx->early_data_phase = 0;
    ctx->early_data_accepted = 0;
    ctx->sent_end_of_early_data = 0;
    ctx->early_data_sent = 0;
    ctx->client_offered_early_data = 0;
    ctx->end_of_early_data_seen = 0;
    ctx->max_early_data_size = 0xFFFFFFFFu;
    ctx->peer_connection_id_len = 0;
    ctx->own_connection_id_len = 0;
    tls13_dtls_peer_cid_pool_clear(ctx);
    tls13_dtls_own_cid_pool_clear(ctx);
    ctx->cid_request_outstanding = 0;
    ctx->cid_new_outstanding = 0;
    ctx->early_seq_num = 0;
    ctx->record_workspace = NULL;
    ctx->record_workspace_owned = 0;
    ctx->handshake_workspace = NULL;
    ctx->handshake_workspace_owned = 0;

    if(use_caller_workspaces) {
        ctx->record_workspace = record_workspace;
        ctx->record_workspace_owned = 0;
        ctx->handshake_workspace = handshake_workspace;
        ctx->handshake_workspace_owned = 0;
    } else {
        /* Reusable record workspace: 2 * (TLS_MAX_RECORD_SIZE + 32) for inner + encrypted (or decrypted) */
        size_t ws_size = (size_t)TLS13_RECORD_WORKSPACE_SIZE;
        ctx->record_workspace = (uint8_t*)noxtls_malloc(ws_size);
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

    /* Zero extensions so noxtls_tls13_context_free can safely call noxtls_tls_extensions_free */
    memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
    memset(&ctx->server_extensions, 0, sizeof(ctx->server_extensions));

    ctx->record_size_limit_send = 0;
    ctx->record_size_limit_recv = 0;

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_tls13_context_init(tls13_context_t *ctx, tls_role_t role)
{
    return tls13_context_init_internal(ctx, role, NULL, 0U, NULL, 0U);
}

noxtls_return_t noxtls_tls13_context_init_with_workspaces(tls13_context_t *ctx,
                                                          tls_role_t role,
                                                          uint8_t *record_workspace,
                                                          uint32_t record_workspace_len,
                                                          uint8_t *handshake_workspace,
                                                          uint32_t handshake_workspace_len)
{
    return tls13_context_init_internal(
        ctx,
        role,
        record_workspace,
        record_workspace_len,
        handshake_workspace,
        handshake_workspace_len);
}

/**
 * @brief Set the maximum plaintext record size this endpoint will receive (RFC 8449).
 * @param[in,out] ctx   TLS 1.3 context.
 * @param[in] limit     Maximum plaintext bytes to accept; 0 uses the default (16384).
 */
void noxtls_tls13_set_record_size_limit(tls13_context_t *ctx, uint16_t limit)
{
    if(ctx != NULL) {
        ctx->record_size_limit_recv = limit;
    }
}

void noxtls_tls13_set_prefer_chacha20(tls13_context_t *ctx, int prefer_chacha20)
{
    if(ctx != NULL) {
        ctx->prefer_chacha20 = prefer_chacha20 ? 1u : 0u;
    }
}

/**
 * @brief Replace TLS 1.3 internal workspaces with caller-provided buffers.
 * @param[in,out] ctx                      TLS 1.3 context (after `noxtls_tls13_context_init`).
 * @param[in] record_workspace             Caller-managed record workspace.
 * @param[in] record_workspace_len         Size of @p record_workspace (at least `TLS13_RECORD_WORKSPACE_SIZE`).
 * @param[in] handshake_workspace          Caller-managed handshake workspace.
 * @param[in] handshake_workspace_len      Size of @p handshake_workspace (at least `TLS_HANDSHAKE_WORKSPACE_SIZE`).
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` or `NOXTLS_RETURN_INVALID_PARAM` on error.
 */
noxtls_return_t tls13_set_workspaces(tls13_context_t *ctx,
                                     uint8_t *record_workspace,
                                     uint32_t record_workspace_len,
                                     uint8_t *handshake_workspace,
                                     uint32_t handshake_workspace_len)
{
    if(ctx == NULL || record_workspace == NULL || handshake_workspace == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(record_workspace_len < (uint32_t)TLS13_RECORD_WORKSPACE_SIZE ||
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
 * @brief Set server RSA private key (`rsa_key_t*`) for CertificateVerify.
 * @param[in,out] ctx      Server context; call before `noxtls_tls13_accept`.
 * @param[in] rsa_key      RSA private key, or NULL to clear.
 */
void noxtls_tls13_set_server_private_rsa(tls13_context_t *ctx, void *rsa_key)
{
    if(ctx != NULL) {
        ctx->server_private_rsa = rsa_key;
        if(rsa_key != NULL) {
            ctx->server_private_ecdsa = NULL;
            ctx->server_ecdsa_matrix_count = 0U;
            memset(ctx->server_ecdsa_matrix_certs, 0, sizeof(ctx->server_ecdsa_matrix_certs));
            memset(ctx->server_ecdsa_matrix_cert_lens, 0, sizeof(ctx->server_ecdsa_matrix_cert_lens));
            memset(ctx->server_ecdsa_matrix_keys, 0, sizeof(ctx->server_ecdsa_matrix_keys));
            memset(ctx->server_private_ed25519, 0, sizeof(ctx->server_private_ed25519));
            ctx->server_cert_use_ed25519 = 0;
            memset(ctx->server_private_ed448, 0, sizeof(ctx->server_private_ed448));
            ctx->server_cert_use_ed448 = 0;
            ctx->server_cert_use_mldsa = 0;
            memset(ctx->server_private_mldsa, 0, sizeof(ctx->server_private_mldsa));
            ctx->server_private_mldsa_len = 0;
            ctx->server_private_mldsa_param = NOXTLS_MLDSA_NONE;
            ctx->server_cert_use_slhdsa = 0;
            memset(ctx->server_private_slhdsa, 0, sizeof(ctx->server_private_slhdsa));
            ctx->server_private_slhdsa_len = 0;
            ctx->server_private_slhdsa_param = NOXTLS_SLHDSA_NONE;
        }
    }
}

/**
 * @brief Set server ECDSA private key (`ecc_key_t*`) for CertificateVerify.
 * @param[in,out] ctx     Server context; call before `noxtls_tls13_accept`.
 * @param[in] ecc_key     ECDSA private key, or NULL to clear.
 */
void noxtls_tls13_set_server_private_ecdsa(tls13_context_t *ctx, void *ecc_key)
{
    if(ctx != NULL) {
        ctx->server_private_ecdsa = ecc_key;
        if(ecc_key != NULL) {
            ctx->server_private_rsa = NULL;
            ctx->server_ecdsa_matrix_count = 0U;
            memset(ctx->server_ecdsa_matrix_certs, 0, sizeof(ctx->server_ecdsa_matrix_certs));
            memset(ctx->server_ecdsa_matrix_cert_lens, 0, sizeof(ctx->server_ecdsa_matrix_cert_lens));
            memset(ctx->server_ecdsa_matrix_keys, 0, sizeof(ctx->server_ecdsa_matrix_keys));
            memset(ctx->server_private_ed25519, 0, sizeof(ctx->server_private_ed25519));
            ctx->server_cert_use_ed25519 = 0;
            memset(ctx->server_private_ed448, 0, sizeof(ctx->server_private_ed448));
            ctx->server_cert_use_ed448 = 0;
            ctx->server_cert_use_mldsa = 0;
            memset(ctx->server_private_mldsa, 0, sizeof(ctx->server_private_mldsa));
            ctx->server_private_mldsa_len = 0;
            ctx->server_private_mldsa_param = NOXTLS_MLDSA_NONE;
            ctx->server_cert_use_slhdsa = 0;
            memset(ctx->server_private_slhdsa, 0, sizeof(ctx->server_private_slhdsa));
            ctx->server_private_slhdsa_len = 0;
            ctx->server_private_slhdsa_param = NOXTLS_SLHDSA_NONE;
        }
    }
}

/**
 * @brief Clear the server ECDSA identity matrix (does not free app-owned keys or certs).
 * @param[in,out] ctx Server context.
 */
void noxtls_tls13_clear_server_ecdsa_identities(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return;
    }
    ctx->server_ecdsa_matrix_count = 0U;
    memset(ctx->server_ecdsa_matrix_certs, 0, sizeof(ctx->server_ecdsa_matrix_certs));
    memset(ctx->server_ecdsa_matrix_cert_lens, 0, sizeof(ctx->server_ecdsa_matrix_cert_lens));
    memset(ctx->server_ecdsa_matrix_keys, 0, sizeof(ctx->server_ecdsa_matrix_keys));
}

/**
 * @brief Add one ECDSA server identity (DER leaf + `ecc_key_t*`) for matrix selection.
 * @param[in,out] ctx      Server context; call only before `noxtls_tls13_accept`.
 * @param[in] cert_der     DER-encoded leaf certificate (non-owning).
 * @param[in] cert_len     Length of @p cert_der.
 * @param[in] ecc_key      Matching ECDSA private key.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` or `NOXTLS_RETURN_INVALID_PARAM` on error.
 */
noxtls_return_t noxtls_tls13_add_server_ecdsa_identity(tls13_context_t *ctx,
                                                       const uint8_t *cert_der,
                                                       uint32_t cert_len,
                                                       void *ecc_key)
{
    uint32_t idx;

    if(ctx == NULL || cert_der == NULL || cert_len == 0U || ecc_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->server_ecdsa_matrix_count >= TLS13_SERVER_ECDSA_MATRIX_MAX) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->server_private_rsa != NULL) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->server_cert_use_ed25519 != 0U || ctx->server_cert_use_ed448 != 0U || ctx->server_cert_use_mldsa != 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    idx = ctx->server_ecdsa_matrix_count;
    if(idx == 0U) {
        ctx->server_private_rsa = NULL;
        memset(ctx->server_private_ed25519, 0, sizeof(ctx->server_private_ed25519));
        ctx->server_cert_use_ed25519 = 0;
        memset(ctx->server_private_ed448, 0, sizeof(ctx->server_private_ed448));
        ctx->server_cert_use_ed448 = 0;
        ctx->server_cert_use_mldsa = 0;
        memset(ctx->server_private_mldsa, 0, sizeof(ctx->server_private_mldsa));
        ctx->server_private_mldsa_len = 0;
        ctx->server_private_mldsa_param = NOXTLS_MLDSA_NONE;
        ctx->server_private_ecdsa = NULL;
    }

    ctx->server_ecdsa_matrix_certs[idx] = cert_der;
    ctx->server_ecdsa_matrix_cert_lens[idx] = cert_len;
    ctx->server_ecdsa_matrix_keys[idx] = ecc_key;
    ctx->server_ecdsa_matrix_count = idx + 1U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Set server Ed25519 private key seed (32 bytes) for CertificateVerify.
 * @param[in,out] ctx             Server context.
 * @param[in] private_key_32      32-byte private key seed.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers.
 */
noxtls_return_t noxtls_tls13_set_server_private_ed25519(tls13_context_t *ctx, const uint8_t *private_key_32)
{
    if(ctx == NULL || private_key_32 == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    memcpy(ctx->server_private_ed25519, private_key_32, 32);
    ctx->server_cert_use_ed25519 = 1;
    memset(ctx->server_private_ed448, 0, sizeof(ctx->server_private_ed448));
    ctx->server_cert_use_ed448 = 0;
    ctx->server_private_rsa = NULL;
    ctx->server_private_ecdsa = NULL;
    ctx->server_ecdsa_matrix_count = 0U;
    memset(ctx->server_ecdsa_matrix_certs, 0, sizeof(ctx->server_ecdsa_matrix_certs));
    memset(ctx->server_ecdsa_matrix_cert_lens, 0, sizeof(ctx->server_ecdsa_matrix_cert_lens));
    memset(ctx->server_ecdsa_matrix_keys, 0, sizeof(ctx->server_ecdsa_matrix_keys));
    ctx->server_cert_use_mldsa = 0;
    memset(ctx->server_private_mldsa, 0, sizeof(ctx->server_private_mldsa));
    ctx->server_private_mldsa_len = 0;
    ctx->server_private_mldsa_param = NOXTLS_MLDSA_NONE;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Set server Ed448 private key seed (57 bytes) for CertificateVerify.
 * @param[in,out] ctx             Server context.
 * @param[in] private_key_57      57-byte private key seed.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` or `NOXTLS_RETURN_NOT_SUPPORTED`.
 */
noxtls_return_t noxtls_tls13_set_server_private_ed448(tls13_context_t *ctx, const uint8_t *private_key_57)
{
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
    if(ctx == NULL || private_key_57 == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    memset(ctx->server_private_ed25519, 0, sizeof(ctx->server_private_ed25519));
    ctx->server_cert_use_ed25519 = 0;
    memcpy(ctx->server_private_ed448, private_key_57, 57);
    ctx->server_cert_use_ed448 = 1;
    ctx->server_private_rsa = NULL;
    ctx->server_private_ecdsa = NULL;
    ctx->server_ecdsa_matrix_count = 0U;
    memset(ctx->server_ecdsa_matrix_certs, 0, sizeof(ctx->server_ecdsa_matrix_certs));
    memset(ctx->server_ecdsa_matrix_cert_lens, 0, sizeof(ctx->server_ecdsa_matrix_cert_lens));
    memset(ctx->server_ecdsa_matrix_keys, 0, sizeof(ctx->server_ecdsa_matrix_keys));
    ctx->server_cert_use_mldsa = 0;
    memset(ctx->server_private_mldsa, 0, sizeof(ctx->server_private_mldsa));
    ctx->server_private_mldsa_len = 0;
    ctx->server_private_mldsa_param = NOXTLS_MLDSA_NONE;
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)ctx;
    (void)private_key_57;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

/**
 * @brief Set server cipher-suite allowlist (wire IDs). Call before handshake.
 * @param[in,out] ctx    Server context.
 * @param[in] suites     Array of cipher suite identifiers (non-owning).
 * @param[in] count      Number of entries in @p suites.
 */
void noxtls_tls13_set_server_cipher_suites(tls13_context_t *ctx, const uint16_t *suites, uint32_t count)
{
    if(ctx == NULL) {
        return;
    }
    ctx->server_cipher_suites = suites;
    ctx->server_cipher_suites_count = count;
}

void noxtls_tls13_set_client_supported_groups(tls13_context_t *ctx, const uint16_t *groups, uint32_t count)
{
    if(ctx == NULL) {
        return;
    }
    ctx->client_supported_groups = groups;
    ctx->client_supported_groups_count = count;
}

void noxtls_tls13_set_client_signature_algorithms(tls13_context_t *ctx, const uint16_t *algorithms, uint32_t count)
{
    if(ctx == NULL) {
        return;
    }
    ctx->client_signature_algorithms = algorithms;
    ctx->client_signature_algorithms_count = count;
}

/**
 * @brief Set supported ALPN protocol names for the server (non-owning).
 * @param[in,out] ctx       Server context.
 * @param[in] protocols     NULL-terminated protocol name pointers.
 * @param[in] count         Number of protocols.
 */
void noxtls_tls13_set_server_alpn_protocols(tls13_context_t *ctx, const char **protocols, uint32_t count)
{
    if(ctx == NULL) {
        return;
    }
    ctx->server_alpn_protocols = protocols;
    ctx->server_alpn_count = count;
}

/**
 * @brief Require ClientHello SNI to match an expected DNS hostname (RFC 6066).
 * @param[in,out] ctx              Server context.
 * @param[in] ascii_hostname       Expected host name, or NULL to disable checking.
 * @param[in] mismatch_fatal       Non-zero to send fatal alert on mismatch.
 */
void noxtls_tls13_set_server_expected_client_sni(tls13_context_t *ctx, const char *ascii_hostname, int mismatch_fatal)
{
    if(ctx == NULL) {
        return;
    }
    ctx->server_expect_client_sni = ascii_hostname;
    ctx->server_expect_sni_fatal = mismatch_fatal ? 1U : 0U;
}

/**
 * @brief Set optional intermediate server certificate chain (DER, non-owning).
 * @param[in,out] ctx         Server context.
 * @param[in] certs           Array of DER certificate pointers.
 * @param[in] cert_lens       Parallel array of certificate lengths.
 * @param[in] cert_count      Number of intermediate certificates.
 */
void noxtls_tls13_set_server_certificate_chain(tls13_context_t *ctx,
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

/**
 * @brief Set optional CRL list for TLS 1.3 peer certificate verification.
 * @param[in,out] ctx  TLS 1.3 context.
 * @param[in] crl      Parsed CRL list head, or NULL to disable CRL checks.
 */
void noxtls_tls13_set_verify_crl(tls13_context_t *ctx, const noxtls_x509_crl_t *crl)
{
    if(ctx != NULL) {
        ctx->verify_crl = crl;
    }
}

/**
 * @brief Set server ML-DSA private key for CertificateVerify.
 * @param[in,out] ctx          Server context.
 * @param[in] param            ML-DSA parameter set (e.g. ML-DSA-65).
 * @param[in] private_key      Secret key bytes of length `noxtls_mldsa_secret_key_len(param)`.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL`, `NOXTLS_RETURN_INVALID_PARAM`, or `NOXTLS_RETURN_NOT_SUPPORTED`.
 */
noxtls_return_t noxtls_tls13_set_server_private_mldsa(tls13_context_t *ctx, noxtls_mldsa_param_t param, const uint8_t *private_key)
{
#if NOXTLS_FEATURE_ML_DSA
    uint32_t sk_len;
    if(ctx == NULL || private_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    sk_len = noxtls_mldsa_secret_key_len(param);
    if(sk_len == 0 || sk_len > sizeof(ctx->server_private_mldsa)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    memset(ctx->server_private_mldsa, 0, sizeof(ctx->server_private_mldsa));
    memcpy(ctx->server_private_mldsa, private_key, sk_len);
    ctx->server_private_mldsa_len = sk_len;
    ctx->server_private_mldsa_param = param;
    ctx->server_cert_use_mldsa = 1;
    ctx->server_private_rsa = NULL;
    ctx->server_private_ecdsa = NULL;
    ctx->server_ecdsa_matrix_count = 0U;
    memset(ctx->server_ecdsa_matrix_certs, 0, sizeof(ctx->server_ecdsa_matrix_certs));
    memset(ctx->server_ecdsa_matrix_cert_lens, 0, sizeof(ctx->server_ecdsa_matrix_cert_lens));
    memset(ctx->server_ecdsa_matrix_keys, 0, sizeof(ctx->server_ecdsa_matrix_keys));
    memset(ctx->server_private_ed25519, 0, sizeof(ctx->server_private_ed25519));
    ctx->server_cert_use_ed25519 = 0;
    memset(ctx->server_private_ed448, 0, sizeof(ctx->server_private_ed448));
    ctx->server_cert_use_ed448 = 0;
    memset(ctx->server_private_slhdsa, 0, sizeof(ctx->server_private_slhdsa));
    ctx->server_private_slhdsa_len = 0U;
    ctx->server_private_slhdsa_param = NOXTLS_SLHDSA_NONE;
    ctx->server_cert_use_slhdsa = 0U;
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)ctx;
    (void)param;
    (void)private_key;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

/**
 * @brief Set server SLH-DSA private key for CertificateVerify.
 * @param[in,out] ctx          Server context.
 * @param[in] param            SLH-DSA parameter set.
 * @param[in] private_key      Secret key bytes of length `noxtls_slhdsa_secret_key_len(param)`.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL`, `NOXTLS_RETURN_INVALID_PARAM`, or `NOXTLS_RETURN_NOT_SUPPORTED`.
 */
noxtls_return_t noxtls_tls13_set_server_private_slhdsa(tls13_context_t *ctx,
                                                       noxtls_slhdsa_param_t param,
                                                       const uint8_t *private_key)
{
#if NOXTLS_FEATURE_SLH_DSA
    uint32_t sk_len;

    if(ctx == NULL || private_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    sk_len = noxtls_slhdsa_secret_key_len(param);
    if(sk_len == 0U || sk_len > sizeof(ctx->server_private_slhdsa)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    memset(ctx->server_private_slhdsa, 0, sizeof(ctx->server_private_slhdsa));
    memcpy(ctx->server_private_slhdsa, private_key, sk_len);
    ctx->server_private_slhdsa_len = sk_len;
    ctx->server_private_slhdsa_param = param;
    ctx->server_cert_use_slhdsa = 1U;
    ctx->server_private_rsa = NULL;
    ctx->server_private_ecdsa = NULL;
    ctx->server_ecdsa_matrix_count = 0U;
    memset(ctx->server_ecdsa_matrix_certs, 0, sizeof(ctx->server_ecdsa_matrix_certs));
    memset(ctx->server_ecdsa_matrix_cert_lens, 0, sizeof(ctx->server_ecdsa_matrix_cert_lens));
    memset(ctx->server_ecdsa_matrix_keys, 0, sizeof(ctx->server_ecdsa_matrix_keys));
    memset(ctx->server_private_ed25519, 0, sizeof(ctx->server_private_ed25519));
    ctx->server_cert_use_ed25519 = 0U;
    memset(ctx->server_private_ed448, 0, sizeof(ctx->server_private_ed448));
    ctx->server_cert_use_ed448 = 0U;
    memset(ctx->server_private_mldsa, 0, sizeof(ctx->server_private_mldsa));
    ctx->server_private_mldsa_len = 0U;
    ctx->server_private_mldsa_param = NOXTLS_MLDSA_NONE;
    ctx->server_cert_use_mldsa = 0U;
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)ctx;
    (void)param;
    (void)private_key;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

/**
 * @brief Server: set Falcon private key for CertificateVerify.
 * @param[in,out] ctx          Server context.
 * @param[in] param            Falcon parameter set.
 * @param[in] private_key      Secret key bytes of length `noxtls_falcon_secret_key_len(param)`.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL`, `NOXTLS_RETURN_INVALID_PARAM`, or `NOXTLS_RETURN_NOT_SUPPORTED`.
 */
noxtls_return_t noxtls_tls13_set_server_private_falcon(tls13_context_t *ctx,
                                                       noxtls_falcon_param_t param,
                                                       const uint8_t *private_key)
{
#if NOXTLS_FEATURE_FALCON
    uint32_t sk_len;
    if(ctx == NULL || private_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    sk_len = noxtls_falcon_secret_key_len(param);
    if(sk_len == 0U || sk_len > sizeof(ctx->server_private_falcon)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    memset(ctx->server_private_falcon, 0, sizeof(ctx->server_private_falcon));
    memcpy(ctx->server_private_falcon, private_key, sk_len);
    ctx->server_private_falcon_len = sk_len;
    ctx->server_private_falcon_param = param;
    ctx->server_cert_use_falcon = 1U;
    ctx->server_private_rsa = NULL;
    ctx->server_private_ecdsa = NULL;
    ctx->server_ecdsa_matrix_count = 0U;
    memset(ctx->server_ecdsa_matrix_certs, 0, sizeof(ctx->server_ecdsa_matrix_certs));
    memset(ctx->server_ecdsa_matrix_cert_lens, 0, sizeof(ctx->server_ecdsa_matrix_cert_lens));
    memset(ctx->server_ecdsa_matrix_keys, 0, sizeof(ctx->server_ecdsa_matrix_keys));
    memset(ctx->server_private_ed25519, 0, sizeof(ctx->server_private_ed25519));
    ctx->server_cert_use_ed25519 = 0U;
    memset(ctx->server_private_ed448, 0, sizeof(ctx->server_private_ed448));
    ctx->server_cert_use_ed448 = 0U;
    memset(ctx->server_private_mldsa, 0, sizeof(ctx->server_private_mldsa));
    ctx->server_private_mldsa_len = 0U;
    ctx->server_private_mldsa_param = NOXTLS_MLDSA_NONE;
    ctx->server_cert_use_mldsa = 0U;
    memset(ctx->server_private_slhdsa, 0, sizeof(ctx->server_private_slhdsa));
    ctx->server_private_slhdsa_len = 0U;
    ctx->server_private_slhdsa_param = NOXTLS_SLHDSA_NONE;
    ctx->server_cert_use_slhdsa = 0U;
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)ctx;
    (void)param;
    (void)private_key;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

/**
 * @brief Server: request a client certificate (mutual TLS). Call before `noxtls_tls13_accept`.
 * @param[in,out] ctx      Server context.
 * @param[in] request      Non-zero to send CertificateRequest.
 */
void noxtls_tls13_request_client_auth(tls13_context_t *ctx, int request)
{
    if(ctx != NULL) {
        ctx->request_client_auth = request ? 1 : 0;
        if(!request) {
            ctx->require_client_auth = 0;
        }
    }
}

/**
 * @brief Server: require a client certificate (implies request). Missing cert yields `certificate_required`.
 * @param[in,out] ctx      Server context.
 * @param[in] require      Non-zero to require client authentication.
 */
void noxtls_tls13_require_client_auth(tls13_context_t *ctx, int require)
{
    if(ctx != NULL) {
        ctx->require_client_auth = require ? 1 : 0;
        if(require) {
            /* Requiring a client cert implies requesting one in handshake. */
            ctx->request_client_auth = 1;
        }
    }
}

/**
 * @brief Client: set DER certificate and RSA private key for mutual TLS.
 * @param[in,out] ctx      Client context; call before `noxtls_tls13_connect`.
 * @param[in] cert_der     Client certificate (DER); copied into context.
 * @param[in] cert_len     Length of @p cert_der.
 * @param[in] rsa_key      `rsa_key_t*` private key.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` or memory error otherwise.
 */
noxtls_return_t noxtls_tls13_set_client_cert(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, void *rsa_key)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(cert_der == NULL || cert_len == 0 || rsa_key == NULL) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->client_cert) {
        free(ctx->client_cert);
        ctx->client_cert = NULL;
    }
    ctx->client_cert = (uint8_t*)malloc(cert_len);
    if(ctx->client_cert == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(ctx->client_cert, cert_der, cert_len);
    ctx->client_cert_len = cert_len;
    ctx->client_private_rsa = rsa_key;
    ctx->client_private_ecdsa = NULL;
    ctx->client_cert_use_ed25519 = 0;
    memset(ctx->client_private_ed25519, 0, sizeof(ctx->client_private_ed25519));
    memset(ctx->client_private_ed448, 0, sizeof(ctx->client_private_ed448));
    ctx->client_cert_use_ed448 = 0;
    memset(ctx->client_private_mldsa, 0, sizeof(ctx->client_private_mldsa));
    ctx->client_private_mldsa_len = 0;
    ctx->client_private_mldsa_param = NOXTLS_MLDSA_NONE;
    ctx->client_cert_use_mldsa = 0;
    memset(ctx->client_private_slhdsa, 0, sizeof(ctx->client_private_slhdsa));
    ctx->client_private_slhdsa_len = 0U;
    ctx->client_private_slhdsa_param = NOXTLS_SLHDSA_NONE;
    ctx->client_cert_use_slhdsa = 0U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Client: set DER certificate and ECDSA private key (`ecc_key_t*`) for mutual TLS.
 * @param[in,out] ctx      Client context.
 * @param[in] cert_der     Client certificate (DER); copied into context.
 * @param[in] cert_len     Length of @p cert_der.
 * @param[in] ecc_key      ECDSA private key.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` or memory error otherwise.
 */
noxtls_return_t noxtls_tls13_set_client_cert_ecdsa(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, void *ecc_key)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(cert_der == NULL || cert_len == 0 || ecc_key == NULL) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->client_cert) {
        free(ctx->client_cert);
        ctx->client_cert = NULL;
    }
    ctx->client_cert = (uint8_t*)malloc(cert_len);
    if(ctx->client_cert == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(ctx->client_cert, cert_der, cert_len);
    ctx->client_cert_len = cert_len;
    ctx->client_private_rsa = NULL;
    ctx->client_private_ecdsa = ecc_key;
    ctx->client_cert_use_ed25519 = 0;
    memset(ctx->client_private_ed25519, 0, sizeof(ctx->client_private_ed25519));
    memset(ctx->client_private_ed448, 0, sizeof(ctx->client_private_ed448));
    ctx->client_cert_use_ed448 = 0;
    memset(ctx->client_private_mldsa, 0, sizeof(ctx->client_private_mldsa));
    ctx->client_private_mldsa_len = 0;
    ctx->client_private_mldsa_param = NOXTLS_MLDSA_NONE;
    ctx->client_cert_use_mldsa = 0;
    memset(ctx->client_private_slhdsa, 0, sizeof(ctx->client_private_slhdsa));
    ctx->client_private_slhdsa_len = 0U;
    ctx->client_private_slhdsa_param = NOXTLS_SLHDSA_NONE;
    ctx->client_cert_use_slhdsa = 0U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Client: set DER certificate and Ed25519 private key seed for mutual TLS.
 * @param[in,out] ctx              Client context.
 * @param[in] cert_der             Client certificate (DER); copied into context.
 * @param[in] cert_len             Length of @p cert_der.
 * @param[in] private_key_32       32-byte Ed25519 private key seed.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` or memory error otherwise.
 */
noxtls_return_t noxtls_tls13_set_client_cert_ed25519(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, const uint8_t *private_key_32)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(cert_der == NULL || cert_len == 0 || private_key_32 == NULL) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->client_cert) {
        free(ctx->client_cert);
        ctx->client_cert = NULL;
    }
    ctx->client_cert = (uint8_t*)malloc(cert_len);
    if(ctx->client_cert == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(ctx->client_cert, cert_der, cert_len);
    ctx->client_cert_len = cert_len;
    ctx->client_private_rsa = NULL;
    ctx->client_private_ecdsa = NULL;
    memcpy(ctx->client_private_ed25519, private_key_32, 32);
    ctx->client_cert_use_ed25519 = 1;
    memset(ctx->client_private_ed448, 0, sizeof(ctx->client_private_ed448));
    ctx->client_cert_use_ed448 = 0;
    memset(ctx->client_private_mldsa, 0, sizeof(ctx->client_private_mldsa));
    ctx->client_private_mldsa_len = 0;
    ctx->client_private_mldsa_param = NOXTLS_MLDSA_NONE;
    ctx->client_cert_use_mldsa = 0;
    memset(ctx->client_private_slhdsa, 0, sizeof(ctx->client_private_slhdsa));
    ctx->client_private_slhdsa_len = 0U;
    ctx->client_private_slhdsa_param = NOXTLS_SLHDSA_NONE;
    ctx->client_cert_use_slhdsa = 0U;
    return NOXTLS_RETURN_SUCCESS;
}

#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
/**
 * @brief Client: set DER certificate and Ed448 private key seed for mutual TLS.
 * @param[in,out] ctx              Client context.
 * @param[in] cert_der             Client certificate (DER); copied into context.
 * @param[in] cert_len             Length of @p cert_der.
 * @param[in] private_key_57       57-byte Ed448 private key seed.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` or memory error otherwise.
 */
noxtls_return_t noxtls_tls13_set_client_cert_ed448(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, const uint8_t *private_key_57)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(cert_der == NULL || cert_len == 0 || private_key_57 == NULL) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->client_cert) {
        free(ctx->client_cert);
        ctx->client_cert = NULL;
    }
    ctx->client_cert = (uint8_t*)malloc(cert_len);
    if(ctx->client_cert == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(ctx->client_cert, cert_der, cert_len);
    ctx->client_cert_len = cert_len;
    ctx->client_private_rsa = NULL;
    ctx->client_private_ecdsa = NULL;
    ctx->client_cert_use_ed25519 = 0;
    memset(ctx->client_private_ed25519, 0, sizeof(ctx->client_private_ed25519));
    memcpy(ctx->client_private_ed448, private_key_57, 57);
    ctx->client_cert_use_ed448 = 1;
    memset(ctx->client_private_mldsa, 0, sizeof(ctx->client_private_mldsa));
    ctx->client_private_mldsa_len = 0;
    ctx->client_private_mldsa_param = NOXTLS_MLDSA_NONE;
    ctx->client_cert_use_mldsa = 0;
    memset(ctx->client_private_slhdsa, 0, sizeof(ctx->client_private_slhdsa));
    ctx->client_private_slhdsa_len = 0U;
    ctx->client_private_slhdsa_param = NOXTLS_SLHDSA_NONE;
    ctx->client_cert_use_slhdsa = 0U;
    return NOXTLS_RETURN_SUCCESS;
}
#else
/**
 * @brief Client: set DER certificate and Ed448 private key seed for mutual TLS.
 * @param[in,out] ctx              Client context.
 * @param[in] cert_der             Client certificate (DER); copied into context.
 * @param[in] cert_len             Length of @p cert_der.
 * @param[in] private_key_57       57-byte Ed448 private key seed.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NOT_SUPPORTED`.
 */
noxtls_return_t noxtls_tls13_set_client_cert_ed448(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, const uint8_t *private_key_57)
{
    (void)ctx;
    (void)cert_der;
    (void)cert_len;
    (void)private_key_57;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}
#endif

/**
 * @brief Client: set DER certificate and ML-DSA private key for mutual TLS.
 * @param[in,out] ctx          Client context.
 * @param[in] cert_der         Client certificate (DER); copied into context.
 * @param[in] cert_len         Length of @p cert_der.
 * @param[in] param            ML-DSA parameter set.
 * @param[in] private_key      ML-DSA secret key bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL`, `NOXTLS_RETURN_INVALID_PARAM`, or `NOXTLS_RETURN_NOT_SUPPORTED`.
 */
noxtls_return_t tls13_set_client_cert_mldsa(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len,
                                            noxtls_mldsa_param_t param, /* NOLINT(bugprone-easily-swappable-parameters): public API preserves cert+param+key tuple. */
                                            const uint8_t *private_key)
{
#if NOXTLS_FEATURE_ML_DSA
    uint32_t sk_len = noxtls_mldsa_secret_key_len(param);
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(cert_der == NULL || cert_len == 0 || private_key == NULL || sk_len == 0 || sk_len > sizeof(ctx->client_private_mldsa)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->client_cert) {
        free(ctx->client_cert);
        ctx->client_cert = NULL;
    }
    ctx->client_cert = (uint8_t*)malloc(cert_len);
    if(ctx->client_cert == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(ctx->client_cert, cert_der, cert_len);
    ctx->client_cert_len = cert_len;
    ctx->client_private_rsa = NULL;
    ctx->client_private_ecdsa = NULL;
    memset(ctx->client_private_ed25519, 0, sizeof(ctx->client_private_ed25519));
    ctx->client_cert_use_ed25519 = 0;
    memset(ctx->client_private_ed448, 0, sizeof(ctx->client_private_ed448));
    ctx->client_cert_use_ed448 = 0;
    memset(ctx->client_private_mldsa, 0, sizeof(ctx->client_private_mldsa));
    memcpy(ctx->client_private_mldsa, private_key, sk_len);
    ctx->client_private_mldsa_len = sk_len;
    ctx->client_private_mldsa_param = param;
    ctx->client_cert_use_mldsa = 1;
    memset(ctx->client_private_slhdsa, 0, sizeof(ctx->client_private_slhdsa));
    ctx->client_private_slhdsa_len = 0U;
    ctx->client_private_slhdsa_param = NOXTLS_SLHDSA_NONE;
    ctx->client_cert_use_slhdsa = 0U;
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)ctx;
    (void)cert_der;
    (void)cert_len;
    (void)param;
    (void)private_key;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

/**
 * @brief Client: set DER certificate and SLH-DSA private key for mutual TLS.
 * @param[in,out] ctx          Client context.
 * @param[in] cert_der         Client certificate (DER); copied into context.
 * @param[in] cert_len         Length of @p cert_der.
 * @param[in] param            SLH-DSA parameter set.
 * @param[in] private_key      SLH-DSA secret key bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL`, `NOXTLS_RETURN_INVALID_PARAM`, or `NOXTLS_RETURN_NOT_SUPPORTED`.
 */
noxtls_return_t tls13_set_client_cert_slhdsa(tls13_context_t *ctx,
                                             const uint8_t *cert_der,
                                             uint32_t cert_len,
                                             noxtls_slhdsa_param_t param, /* NOLINT(bugprone-easily-swappable-parameters): public API preserves cert+param+key tuple. */
                                             const uint8_t *private_key)
{
#if NOXTLS_FEATURE_SLH_DSA
    uint32_t sk_len = noxtls_slhdsa_secret_key_len(param);

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(cert_der == NULL || cert_len == 0U || private_key == NULL ||
       sk_len == 0U || sk_len > sizeof(ctx->client_private_slhdsa)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->client_cert) {
        free(ctx->client_cert);
        ctx->client_cert = NULL;
    }
    ctx->client_cert = (uint8_t*)malloc(cert_len);
    if(ctx->client_cert == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(ctx->client_cert, cert_der, cert_len);
    ctx->client_cert_len = cert_len;
    ctx->client_private_rsa = NULL;
    ctx->client_private_ecdsa = NULL;
    memset(ctx->client_private_ed25519, 0, sizeof(ctx->client_private_ed25519));
    ctx->client_cert_use_ed25519 = 0U;
    memset(ctx->client_private_ed448, 0, sizeof(ctx->client_private_ed448));
    ctx->client_cert_use_ed448 = 0U;
    memset(ctx->client_private_mldsa, 0, sizeof(ctx->client_private_mldsa));
    ctx->client_private_mldsa_len = 0U;
    ctx->client_private_mldsa_param = NOXTLS_MLDSA_NONE;
    ctx->client_cert_use_mldsa = 0U;
    memset(ctx->client_private_slhdsa, 0, sizeof(ctx->client_private_slhdsa));
    memcpy(ctx->client_private_slhdsa, private_key, sk_len);
    ctx->client_private_slhdsa_len = sk_len;
    ctx->client_private_slhdsa_param = param;
    ctx->client_cert_use_slhdsa = 1U;
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)ctx;
    (void)cert_der;
    (void)cert_len;
    (void)param;
    (void)private_key;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

/**
 * @brief Set the client certificate and Falcon private key
 *
 * @param[in] ctx The context to set the client certificate and Falcon private key from
 * @param[in] cert_der The certificate to set the client certificate and Falcon private key from
 * @param[in] cert_len The length of the certificate to set the client certificate and Falcon private key from
 * @param[in] param The Falcon parameter to set the client certificate and Falcon private key from
 * @param[in] private_key The Falcon private key to set the client certificate and Falcon private key from
 * @return The return code
 */
noxtls_return_t tls13_set_client_cert_falcon(tls13_context_t *ctx,
                                             const uint8_t *cert_der,
                                             uint32_t cert_len,
                                             noxtls_falcon_param_t param,
                                             const uint8_t *private_key)
{
#if NOXTLS_FEATURE_FALCON
    uint32_t sk_len = noxtls_falcon_secret_key_len(param);
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(cert_der == NULL || cert_len == 0U || private_key == NULL ||
       sk_len == 0U || sk_len > sizeof(ctx->client_private_falcon)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->client_cert) {
        free(ctx->client_cert);
        ctx->client_cert = NULL;
    }
    ctx->client_cert = (uint8_t*)malloc(cert_len);
    if(ctx->client_cert == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(ctx->client_cert, cert_der, cert_len);
    ctx->client_cert_len = cert_len;
    ctx->client_private_rsa = NULL;
    ctx->client_private_ecdsa = NULL;
    memset(ctx->client_private_ed25519, 0, sizeof(ctx->client_private_ed25519));
    ctx->client_cert_use_ed25519 = 0U;
    memset(ctx->client_private_ed448, 0, sizeof(ctx->client_private_ed448));
    ctx->client_cert_use_ed448 = 0U;
    memset(ctx->client_private_mldsa, 0, sizeof(ctx->client_private_mldsa));
    ctx->client_private_mldsa_len = 0U;
    ctx->client_private_mldsa_param = NOXTLS_MLDSA_NONE;
    ctx->client_cert_use_mldsa = 0U;
    memset(ctx->client_private_slhdsa, 0, sizeof(ctx->client_private_slhdsa));
    ctx->client_private_slhdsa_len = 0U;
    ctx->client_private_slhdsa_param = NOXTLS_SLHDSA_NONE;
    ctx->client_cert_use_slhdsa = 0U;
    memset(ctx->client_private_falcon, 0, sizeof(ctx->client_private_falcon));
    memcpy(ctx->client_private_falcon, private_key, sk_len);
    ctx->client_private_falcon_len = sk_len;
    ctx->client_private_falcon_param = param;
    ctx->client_cert_use_falcon = 1U;
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)ctx;
    (void)cert_der;
    (void)cert_len;
    (void)param;
    (void)private_key;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

/**
 * @brief Configure external PSK identity and key for TLS 1.3 PSK or ECDHE-PSK handshakes.
 * @param[in,out] ctx              Context; call before connect/accept.
 * @param[in] identity             PSK identity bytes.
 * @param[in] identity_len         Length of @p identity.
 * @param[in] psk_key              Pre-shared key bytes.
 * @param[in] psk_key_len          Length of @p psk_key.
 * @param[in] preferred_mode       `TLS13_PSK_KE_MODE_PSK_KE` or `TLS13_PSK_KE_MODE_PSK_DHE_KE`.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` or `NOXTLS_RETURN_INVALID_PARAM` on error.
 *
 * NOLINTBEGIN(bugprone-easily-swappable-parameters)
 */
noxtls_return_t tls13_set_external_psk(tls13_context_t *ctx,
                                       const uint8_t *identity, uint16_t identity_len, /* NOLINT(bugprone-easily-swappable-parameters): identity/key length pairs intentionally adjacent. */
                                       const uint8_t *psk_key, uint16_t psk_key_len,
                                       uint8_t preferred_mode)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    if(ctx == NULL || identity == NULL || psk_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(identity_len == 0 || identity_len > sizeof(ctx->psk_identity) ||
       psk_key_len == 0 || psk_key_len > sizeof(ctx->psk_key)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(preferred_mode != TLS13_PSK_KE_MODE_PSK_KE &&
       preferred_mode != TLS13_PSK_KE_MODE_PSK_DHE_KE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    memset(ctx->psk_identity, 0, sizeof(ctx->psk_identity));
    memcpy(ctx->psk_identity, identity, identity_len);
    ctx->psk_identity_len = identity_len;
    memset(ctx->psk_key, 0, sizeof(ctx->psk_key));
    memcpy(ctx->psk_key, psk_key, psk_key_len);
    ctx->psk_key_len = psk_key_len;
    ctx->psk_configured = 1;
    ctx->psk_preferred_mode = preferred_mode;
    ctx->psk_in_use = 0;
    ctx->psk_use_ecdhe = 0;
    ctx->psk_selected_identity = 0;
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
    
    if(ctx->server_cert) {
        if(ctx->base.base.role == TLS_ROLE_CLIENT) {
            free(ctx->server_cert);
        }
        ctx->server_cert = NULL;
    }
    
    if(ctx->server_cert_parsed) {
        noxtls_x509_certificate_free((x509_certificate_t*)ctx->server_cert_parsed);
        free(ctx->server_cert_parsed);
        ctx->server_cert_parsed = NULL;
    }
    ctx->server_ecdsa_matrix_count = 0U;
    memset(ctx->server_ecdsa_matrix_certs, 0, sizeof(ctx->server_ecdsa_matrix_certs));
    memset(ctx->server_ecdsa_matrix_cert_lens, 0, sizeof(ctx->server_ecdsa_matrix_cert_lens));
    memset(ctx->server_ecdsa_matrix_keys, 0, sizeof(ctx->server_ecdsa_matrix_keys));
    if(ctx->client_cert) {
        free(ctx->client_cert);
        ctx->client_cert = NULL;
    }
    ctx->client_cert_len = 0;
    ctx->client_private_rsa = NULL;
    ctx->client_private_ecdsa = NULL;
    memset(ctx->client_private_ed25519, 0, sizeof(ctx->client_private_ed25519));
    ctx->client_cert_use_ed25519 = 0;
    memset(ctx->client_private_ed448, 0, sizeof(ctx->client_private_ed448));
    ctx->client_cert_use_ed448 = 0;
    if(ctx->client_cert_parsed) {
        noxtls_x509_certificate_free((x509_certificate_t*)ctx->client_cert_parsed);
        free(ctx->client_cert_parsed);
        ctx->client_cert_parsed = NULL;
    }
    if(ctx->pending_handshake_msg) {
        free(ctx->pending_handshake_msg);
        ctx->pending_handshake_msg = NULL;
    }
    ctx->pending_handshake_len = 0;
    
    if(ctx->handshake_messages) {
        free(ctx->handshake_messages);
        ctx->handshake_messages = NULL;
    }
    if(ctx->client_tls12_downgrade_server_hello) {
        free(ctx->client_tls12_downgrade_server_hello);
        ctx->client_tls12_downgrade_server_hello = NULL;
        ctx->client_tls12_downgrade_server_hello_len = 0;
    }
    if(ctx->handshake_buffer) {
        free(ctx->handshake_buffer);
        ctx->handshake_buffer = NULL;
    }
    ctx->handshake_buffer_len = 0;
    ctx->handshake_buffer_pos = 0;
    ctx->handshake_next_at_record_boundary = 0;
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

    tls13_free_client_key_shares(ctx);
    
    tls13_free_server_key_share(ctx);
    tls13_release_ecdhe_ctx(ctx);
    
    /* Free extensions */
    noxtls_tls_extensions_free(&ctx->client_extensions);
    noxtls_tls_extensions_free(&ctx->server_extensions);

    if(ctx->hrr_first_clienthello_ext_order != NULL) {
        free(ctx->hrr_first_clienthello_ext_order);
        ctx->hrr_first_clienthello_ext_order = NULL;
    }
    ctx->hrr_first_clienthello_ext_order_count = 0;

    memset(ctx->psk_key, 0, sizeof(ctx->psk_key));
    ctx->psk_key_len = 0;
    ctx->psk_configured = 0;
    ctx->psk_in_use = 0;
    ctx->psk_use_ecdhe = 0;

    if(ctx->pending_app_data) {
        free(ctx->pending_app_data);
        ctx->pending_app_data = NULL;
    }
    ctx->pending_app_data_len = 0;
    memset(ctx->ticket_identity, 0, sizeof(ctx->ticket_identity));
    memset(ctx->ticket_nonce, 0, sizeof(ctx->ticket_nonce));
    memset(ctx->resumption_psk, 0, sizeof(ctx->resumption_psk));
    memset(ctx->ffdhe_shared_secret, 0, sizeof(ctx->ffdhe_shared_secret));
    ctx->ticket_stored = 0;
    ctx->ffdhe_shared_secret_len = 0;
    memset(ctx->mlkem_client_public_key, 0, sizeof(ctx->mlkem_client_public_key));
    memset(ctx->mlkem_client_secret_key, 0, sizeof(ctx->mlkem_client_secret_key));
    memset(ctx->mlkem_server_public_key, 0, sizeof(ctx->mlkem_server_public_key));
    memset(ctx->mlkem_server_secret_key, 0, sizeof(ctx->mlkem_server_secret_key));
    memset(ctx->hybrid_shared_secret, 0, sizeof(ctx->hybrid_shared_secret));
    ctx->hybrid_shared_secret_len = 0;
    ctx->server_private_ecdsa = NULL;
    memset(ctx->server_private_ed25519, 0, sizeof(ctx->server_private_ed25519));
    ctx->server_cert_use_ed25519 = 0;
    memset(ctx->server_private_ed448, 0, sizeof(ctx->server_private_ed448));
    ctx->server_cert_use_ed448 = 0;
    ctx->selected_kex_group = 0;
    ctx->selected_kex_is_hybrid = 0;
    ctx->selected_mlkem_param = NOXTLS_MLKEM_NONE;
    memset(ctx->server_private_mldsa, 0, sizeof(ctx->server_private_mldsa));
    ctx->server_private_mldsa_len = 0;
    ctx->server_private_mldsa_param = NOXTLS_MLDSA_NONE;
    ctx->server_cert_use_mldsa = 0;
    memset(ctx->server_private_slhdsa, 0, sizeof(ctx->server_private_slhdsa));
    ctx->server_private_slhdsa_len = 0;
    ctx->server_private_slhdsa_param = NOXTLS_SLHDSA_NONE;
    ctx->server_cert_use_slhdsa = 0;
    memset(ctx->client_private_mldsa, 0, sizeof(ctx->client_private_mldsa));
    ctx->client_private_mldsa_len = 0;
    ctx->client_private_mldsa_param = NOXTLS_MLDSA_NONE;
    ctx->client_cert_use_mldsa = 0;
    memset(ctx->client_private_slhdsa, 0, sizeof(ctx->client_private_slhdsa));
    ctx->client_private_slhdsa_len = 0;
    ctx->client_private_slhdsa_param = NOXTLS_SLHDSA_NONE;
    ctx->client_cert_use_slhdsa = 0;

    noxtls_dtls_context_free(&ctx->base);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Client: construct and send ClientHello (key shares, cipher suites, extensions).
 * @param[in,out] ctx Client context with transport initialized.
 * @return `NOXTLS_RETURN_SUCCESS` on success; error codes for DRBG, encoding, send, or memory failure.
 */
noxtls_return_t noxtls_tls13_send_client_hello(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    uint8_t *client_hello = ctx->handshake_workspace;
    if(client_hello == NULL) {
        client_hello = (uint8_t*)noxtls_malloc(TLS_CLIENT_HELLO_DEFAULT_SIZE);
        if(client_hello == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    uint32_t offset = 0;
    drbg_state_t drbg_state;
    uint16_t cipher_suites[] = {
        TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
        TLS_CIPHER_SUITE_AES_128_CCM_SHA256,
        TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256,
        TLS_CIPHER_SUITE_AES_256_GCM_SHA384,
        TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256
        /* Note: ARIA GCM suites for TLS 1.3 would need to be defined if supported */
    };
    uint16_t supported_groups[12];
    uint16_t signature_algorithms[16];
    const uint16_t *supported_groups_list = supported_groups;
    const uint16_t *signature_algorithms_list = signature_algorithms;
    uint32_t supported_groups_count;
    uint32_t signature_algorithms_count;
    uint8_t key_share_entries[4096];
    uint32_t key_share_entries_len = 0;
    tls_ecdhe_context_t *ecdhe_ctx = NULL;
    int offer_psk = 0;
    int offer_resumption = 0;
    int offer_external_psk = 0;
    int include_key_share = 1;
    int resend_after_hrr = 0;
    noxtls_hash_algos_t psk_hash_algo = NOXTLS_HASH_SHA_256;
    uint32_t psk_hash_len = 0;
    uint32_t psk_key_len = 0;
    const uint8_t *binder_transcript_prefix = NULL;
    uint32_t binder_transcript_prefix_len = 0U;
    uint32_t resumption_binder_offset = 0;
    uint32_t external_binder_offset = 0;
    uint16_t psk_binder_len = 0;
    const uint8_t *dtls_hrr_cookie = NULL;
    uint32_t dtls_hrr_cookie_len = 0;
    
    ctx->psk_in_use = 0;
    ctx->psk_use_ecdhe = 0;
    ctx->psk_selected_identity = 0;
    offer_resumption = (ctx->ticket_stored && ctx->ticket_identity_len > 0 && ctx->resumption_psk_len > 0);
    offer_external_psk = (ctx->psk_configured && ctx->psk_identity_len > 0 && ctx->psk_key_len > 0);
    offer_psk = offer_resumption || offer_external_psk;
    if((ctx->client_supported_groups != NULL) && (ctx->client_supported_groups_count > 0U)) {
        supported_groups_list = ctx->client_supported_groups;
        supported_groups_count = ctx->client_supported_groups_count;
    } else {
        supported_groups_count = tls13_build_supported_groups(supported_groups, 12U);
    }
    if((ctx->client_signature_algorithms != NULL) && (ctx->client_signature_algorithms_count > 0U)) {
        signature_algorithms_list = ctx->client_signature_algorithms;
        signature_algorithms_count = ctx->client_signature_algorithms_count;
    } else {
        signature_algorithms_count = tls13_build_signature_algorithms(signature_algorithms, 16U);
    }
    if(offer_psk) {
        uint16_t cs = offer_resumption ? ctx->ticket_cipher_suite : cipher_suites[0];
        if(tls13_get_cipher_params(cs, &psk_hash_algo, &psk_hash_len, &psk_key_len) != NOXTLS_RETURN_SUCCESS) {
            tls13_connect_log_fail(ctx, "send_client_hello/get_cipher_params", NOXTLS_RETURN_FAILED);
            if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
    }
    if(ctx->received_hrr ||
       (ctx->handshake_messages != NULL &&
        ctx->handshake_messages_len > 0U &&
        ctx->handshake_messages[0] == TLS_HANDSHAKE_MESSAGE_HASH)) {
        resend_after_hrr = 1;
        binder_transcript_prefix = ctx->handshake_messages;
        binder_transcript_prefix_len = ctx->handshake_messages_len;
    } else if(tls13_is_dtls(ctx) && ctx->base.hrr_cookie != NULL) {
        noxtls_free(ctx->base.hrr_cookie);
        ctx->base.hrr_cookie = NULL;
        ctx->base.hrr_cookie_len = 0;
    }
    if(tls13_is_dtls(ctx) && resend_after_hrr && ctx->base.hrr_cookie != NULL && ctx->base.hrr_cookie_len > 0U) {
        dtls_hrr_cookie = ctx->base.hrr_cookie;
        dtls_hrr_cookie_len = ctx->base.hrr_cookie_len;
    }
    include_key_share = (!offer_psk || ctx->psk_preferred_mode == TLS13_PSK_KE_MODE_PSK_DHE_KE);
    
    /* Generate ClientHello.random once and reuse it across HRR retries. */
    if(drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        tls13_connect_log_fail(ctx, "send_client_hello/drbg_instantiate", NOXTLS_RETURN_FAILED);
        if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    if(!resend_after_hrr) {
        if(drbg_generate(&drbg_state, ctx->client_random, sizeof(ctx->client_random) * 8U, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
            tls13_connect_log_fail(ctx, "send_client_hello/drbg_generate_random", NOXTLS_RETURN_FAILED);
            if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
    }
    noxtls_debug_printf("[TLS13_DEBUG] client_random=");
    for(uint32_t i = 0; i < 32; i++) {
        noxtls_debug_printf("%02X", ctx->client_random[i]);
    }
    noxtls_debug_printf("\n");
    if(tls13_is_dtls(ctx)) {
        noxtls_debug_printf("[TLS13_DEBUG] send_client_hello: dtls cookie_len=%u\n",
                            (unsigned)ctx->base.cookie_len);
        noxtls_debug_printf("[TLS13_DEBUG] send_client_hello: resend_after_hrr=%u received_hrr=%u transcript_len=%lu\n",
                            (unsigned)resend_after_hrr,
                            (unsigned)ctx->received_hrr,
                            (unsigned long)ctx->handshake_messages_len);
    }
    
    /* Build Client Hello noxtls_message */
    client_hello[offset++] = TLS_HANDSHAKE_CLIENT_HELLO;
    client_hello[offset++] = 0x00;  /* Length (3 bytes) - placeholder */
    client_hello[offset++] = 0x00;
    client_hello[offset++] = 0x00;
    
    /* Legacy version (for compatibility) */
    if(tls13_is_dtls(ctx)) {
        client_hello[offset++] = (DTLS_VERSION_1_2 >> 8) & 0xFF;
        client_hello[offset++] = DTLS_VERSION_1_2 & 0xFF;
    } else {
        client_hello[offset++] = 0x03;
        client_hello[offset++] = 0x03;
    }
    
    /* Random (32 bytes) */
    memcpy(client_hello + offset, ctx->client_random, TLS_RANDOM_SIZE);
    offset += TLS_RANDOM_SIZE;
    
    /* Legacy session ID length (1 byte). DTLS 1.3 clients use an empty legacy_session_id by default. */
    uint8_t session_id[TLS_SESSION_ID_MAX_LEN];
    if(tls13_is_dtls(ctx)) {
        client_hello[offset++] = 0x00;
        client_hello[offset++] = 0x00;  /* legacy_cookie length */
    } else {
        if(drbg_generate(&drbg_state, session_id, sizeof(session_id) * 8U, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
            tls13_connect_log_fail(ctx, "send_client_hello/drbg_generate_session_id", NOXTLS_RETURN_FAILED);
            if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        client_hello[offset++] = (uint8_t)sizeof(session_id);
        memcpy(client_hello + offset, session_id, sizeof(session_id));
        offset += sizeof(session_id);
    }
    
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
    
    tls13_free_client_key_shares(ctx);
    if(include_key_share) {
        uint8_t encoded_entry[TLS_KEY_SHARE_ENTRY_MAX_LEN];
        uint32_t encoded_entry_len = sizeof(encoded_entry);
        uint32_t shares_capacity = 1U;
        tls13_key_share_entry_t *shares = &ctx->client_key_share_inline;

#if NOXTLS_FEATURE_ML_KEM
        shares_capacity = 3U;
        shares = (tls13_key_share_entry_t*)calloc(shares_capacity, sizeof(tls13_key_share_entry_t));
        if(shares == NULL) {
            tls13_connect_log_fail(ctx, "send_client_hello/alloc_client_shares", NOXTLS_RETURN_NOT_ENOUGH_MEMORY);
            if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
#else
        memset(&ctx->client_key_share_inline, 0, sizeof(ctx->client_key_share_inline));
        memset(ctx->client_key_share_inline_buf, 0, sizeof(ctx->client_key_share_inline_buf));
#endif

        if(ctx->ecdhe_ctx == NULL) {
            ecdhe_ctx = &ctx->ecdhe_ctx_inline;
            memset(ecdhe_ctx, 0, sizeof(*ecdhe_ctx));
            if(noxtls_tls_ecdhe_context_init(ecdhe_ctx, TLS_NAMED_GROUP_X25519) != NOXTLS_RETURN_SUCCESS ||
               noxtls_tls_ecdhe_generate_ephemeral_key(ecdhe_ctx) != NOXTLS_RETURN_SUCCESS) {
                tls13_connect_log_fail(ctx, "send_client_hello/init_ecdhe", NOXTLS_RETURN_FAILED);
                noxtls_tls_ecdhe_context_free(ecdhe_ctx);
#if NOXTLS_FEATURE_ML_KEM
                free(shares);
#endif
                if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return NOXTLS_RETURN_FAILED;
            }
            ctx->ecdhe_ctx = ecdhe_ctx;
        } else {
            ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
        }

        if(ecdhe_ctx->named_group != TLS_NAMED_GROUP_X25519) {
            noxtls_tls_ecdhe_context_free(ecdhe_ctx);
            if(noxtls_tls_ecdhe_context_init(ecdhe_ctx, TLS_NAMED_GROUP_X25519) != NOXTLS_RETURN_SUCCESS ||
               noxtls_tls_ecdhe_generate_ephemeral_key(ecdhe_ctx) != NOXTLS_RETURN_SUCCESS) {
                tls13_connect_log_fail(ctx, "send_client_hello/reinit_ecdhe", NOXTLS_RETURN_FAILED);
#if NOXTLS_FEATURE_ML_KEM
                free(shares);
#endif
                if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return NOXTLS_RETURN_FAILED;
            }
        }

        if(noxtls_tls13_key_share_encode(ecdhe_ctx, encoded_entry, &encoded_entry_len) != NOXTLS_RETURN_SUCCESS ||
           key_share_entries_len + encoded_entry_len > sizeof(key_share_entries)) {
            tls13_connect_log_fail(ctx, "send_client_hello/key_share_encode", NOXTLS_RETURN_FAILED);
#if NOXTLS_FEATURE_ML_KEM
            free(shares);
#endif
            if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(key_share_entries + key_share_entries_len, encoded_entry, encoded_entry_len);
        key_share_entries_len += encoded_entry_len;
        shares[0].group = TLS_NAMED_GROUP_X25519;
        shares[0].key_exchange_len = (uint16_t)(encoded_entry_len - 4U);
        if(shares[0].key_exchange_len <= sizeof(ctx->client_key_share_inline_buf)) {
            shares[0].key_exchange = ctx->client_key_share_inline_buf;
        } else {
            shares[0].key_exchange = (uint8_t*)malloc(shares[0].key_exchange_len);
        }
        if(shares[0].key_exchange == NULL) {
            tls13_connect_log_fail(ctx, "send_client_hello/alloc_key_exchange", NOXTLS_RETURN_NOT_ENOUGH_MEMORY);
#if NOXTLS_FEATURE_ML_KEM
            free(shares);
#endif
            if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(shares[0].key_exchange, encoded_entry + 4, shares[0].key_exchange_len);
        ctx->client_key_shares_count = 1;

#if NOXTLS_FEATURE_ML_KEM
        {
            noxtls_mlkem_param_t mlkem_param = NOXTLS_MLKEM_768;
            uint32_t mlkem_pk_len = noxtls_mlkem_public_key_len(mlkem_param);
            uint32_t mlkem_sk_len = noxtls_mlkem_secret_key_len(mlkem_param);
            if(noxtls_mlkem_keygen(mlkem_param, ctx->mlkem_client_public_key, ctx->mlkem_client_secret_key) == NOXTLS_RETURN_SUCCESS &&
               mlkem_pk_len > 0 && mlkem_sk_len > 0) {
                uint8_t *hybrid_payload;
                uint32_t hybrid_len = (uint32_t)(NOXTLS_X25519_KEY_SIZE + mlkem_pk_len);

                ctx->mlkem_client_public_key_len = mlkem_pk_len;
                ctx->mlkem_client_secret_key_len = mlkem_sk_len;

                if(key_share_entries_len + 4U + mlkem_pk_len <= sizeof(key_share_entries) && ctx->client_key_shares_count < shares_capacity) {
                    tls13_write_uint16(key_share_entries + key_share_entries_len, TLS_NAMED_GROUP_MLKEM768);
                    tls13_write_uint16(key_share_entries + key_share_entries_len + 2U, (uint16_t)mlkem_pk_len);
                    memcpy(key_share_entries + key_share_entries_len + 4U, ctx->mlkem_client_public_key, mlkem_pk_len);
                    key_share_entries_len += 4U + mlkem_pk_len;

                    shares[ctx->client_key_shares_count].group = TLS_NAMED_GROUP_MLKEM768;
                    shares[ctx->client_key_shares_count].key_exchange_len = (uint16_t)mlkem_pk_len;
                    shares[ctx->client_key_shares_count].key_exchange = (uint8_t*)malloc(mlkem_pk_len);
                    if(shares[ctx->client_key_shares_count].key_exchange == NULL) {
                        if(shares[0].key_exchange != ctx->client_key_share_inline_buf) {
                            free(shares[0].key_exchange);
                        }
                        free(shares);
                        if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                        return NOXTLS_RETURN_FAILED;
                    }
                    memcpy(shares[ctx->client_key_shares_count].key_exchange, ctx->mlkem_client_public_key, mlkem_pk_len);
                    ctx->client_key_shares_count++;
                }

                if(key_share_entries_len + 4U + hybrid_len <= sizeof(key_share_entries) && ctx->client_key_shares_count < shares_capacity) {
                    tls13_write_uint16(key_share_entries + key_share_entries_len, TLS_NAMED_GROUP_X25519_MLKEM768);
                    tls13_write_uint16(key_share_entries + key_share_entries_len + 2U, (uint16_t)hybrid_len);
                    key_share_entries_len += 4U;
                    memcpy(key_share_entries + key_share_entries_len, ctx->mlkem_client_public_key, mlkem_pk_len);
                    key_share_entries_len += mlkem_pk_len;
                    memcpy(key_share_entries + key_share_entries_len, ecdhe_ctx->x25519_public_key, NOXTLS_X25519_KEY_SIZE);
                    key_share_entries_len += NOXTLS_X25519_KEY_SIZE;

                    shares[ctx->client_key_shares_count].group = TLS_NAMED_GROUP_X25519_MLKEM768;
                    shares[ctx->client_key_shares_count].key_exchange_len = (uint16_t)hybrid_len;
                    hybrid_payload = (uint8_t*)malloc(hybrid_len);
                    shares[ctx->client_key_shares_count].key_exchange = hybrid_payload;
                    if(hybrid_payload == NULL) {
                        if(shares[0].key_exchange != ctx->client_key_share_inline_buf) {
                            free(shares[0].key_exchange);
                        }
                        free(shares[1].key_exchange);
                        free(shares);
                        if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                        return NOXTLS_RETURN_FAILED;
                    }
                    {
                        uint32_t h_off = 0;
                        memcpy(hybrid_payload + h_off, ctx->mlkem_client_public_key, mlkem_pk_len);
                        h_off += mlkem_pk_len;
                        memcpy(hybrid_payload + h_off, ecdhe_ctx->x25519_public_key, NOXTLS_X25519_KEY_SIZE);
                        ctx->client_key_shares_count++;
                    }
                }
            }
        }
#endif
        ctx->client_key_shares = shares;
    }
    
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
    if(tls13_is_dtls(ctx)) {
        client_hello[offset++] = 0x00;
        client_hello[offset++] = 0x03;
        client_hello[offset++] = 0x02;
        client_hello[offset++] = (DTLS_VERSION_1_3 >> 8) & 0xFF;
        client_hello[offset++] = DTLS_VERSION_1_3 & 0xFF;
    } else {
        client_hello[offset++] = 0x00;
        client_hello[offset++] = 0x05;
        client_hello[offset++] = 0x04;
        client_hello[offset++] = 0x03;
        client_hello[offset++] = 0x04;
        client_hello[offset++] = 0x03;
        client_hello[offset++] = 0x03;
    }

    /* Supported Groups */
    client_hello[offset++] = (TLS_EXTENSION_SUPPORTED_GROUPS >> 8) & 0xFF;
    client_hello[offset++] = TLS_EXTENSION_SUPPORTED_GROUPS & 0xFF;
    uint16_t groups_len = (uint16_t)(supported_groups_count * sizeof(uint16_t));
    client_hello[offset++] = (uint8_t)((groups_len + 2) >> 8);
    client_hello[offset++] = (uint8_t)((groups_len + 2) & 0xFF);
    client_hello[offset++] = (groups_len >> 8) & 0xFF;
    client_hello[offset++] = groups_len & 0xFF;
    for(uint32_t i = 0; i < supported_groups_count; i++) {
        client_hello[offset++] = (supported_groups_list[i] >> 8) & 0xFF;
        client_hello[offset++] = supported_groups_list[i] & 0xFF;
    }

    /* Signature Algorithms */
    client_hello[offset++] = (TLS_EXTENSION_SIGNATURE_ALGORITHMS >> 8) & 0xFF;
    client_hello[offset++] = TLS_EXTENSION_SIGNATURE_ALGORITHMS & 0xFF;
    uint16_t sig_len = (uint16_t)(signature_algorithms_count * sizeof(uint16_t));
    client_hello[offset++] = (uint8_t)((sig_len + 2) >> 8);
    client_hello[offset++] = (uint8_t)((sig_len + 2) & 0xFF);
    client_hello[offset++] = (sig_len >> 8) & 0xFF;
    client_hello[offset++] = sig_len & 0xFF;
    for(uint32_t i = 0; i < signature_algorithms_count; i++) {
        client_hello[offset++] = (signature_algorithms_list[i] >> 8) & 0xFF;
        client_hello[offset++] = signature_algorithms_list[i] & 0xFF;
    }

    /* RFC 8449 Record Size Limit: max plaintext we are willing to receive */
    if(ctx->record_size_limit_recv > 0) {
        uint16_t rsl = ctx->record_size_limit_recv;
        client_hello[offset++] = (TLS_EXTENSION_RECORD_SIZE_LIMIT >> 8) & 0xFF;
        client_hello[offset++] = TLS_EXTENSION_RECORD_SIZE_LIMIT & 0xFF;
        client_hello[offset++] = 0x00;
        client_hello[offset++] = 0x02;
        client_hello[offset++] = (rsl >> 8) & 0xFF;
        client_hello[offset++] = rsl & 0xFF;
    }

    /* Key Share (required for normal TLS 1.3 and ECDHE-PSK) */
    if(include_key_share) {
        uint16_t key_share_list_len = (uint16_t)key_share_entries_len;
        uint16_t key_share_ext_len = (uint16_t)(key_share_entries_len + 2U);
        client_hello[offset++] = (TLS_EXTENSION_KEY_SHARE >> 8) & 0xFF;
        client_hello[offset++] = TLS_EXTENSION_KEY_SHARE & 0xFF;
        client_hello[offset++] = (key_share_ext_len >> 8) & 0xFF;
        client_hello[offset++] = key_share_ext_len & 0xFF;
        client_hello[offset++] = (key_share_list_len >> 8) & 0xFF;
        client_hello[offset++] = key_share_list_len & 0xFF;
        memcpy(client_hello + offset, key_share_entries, key_share_entries_len);
        offset += key_share_entries_len;
    }

    /* Cookie (DTLS 1.3 HelloRetryRequest) */
    if(tls13_is_dtls(ctx) && (dtls_hrr_cookie_len > 0U || ctx->base.cookie_len > 0U)) {
        const uint8_t *cookie_data = (dtls_hrr_cookie_len > 0U) ? dtls_hrr_cookie : ctx->base.cookie;
        uint16_t cookie_len = (uint16_t)((dtls_hrr_cookie_len > 0U) ? dtls_hrr_cookie_len : ctx->base.cookie_len);
        uint16_t cookie_ext_len = (uint16_t)(2U + cookie_len);
        client_hello[offset++] = (TLS_EXTENSION_COOKIE >> 8) & 0xFF;
        client_hello[offset++] = TLS_EXTENSION_COOKIE & 0xFF;
        client_hello[offset++] = (cookie_ext_len >> 8) & 0xFF;
        client_hello[offset++] = cookie_ext_len & 0xFF;
        client_hello[offset++] = (cookie_len >> 8) & 0xFF;
        client_hello[offset++] = cookie_len & 0xFF;
        memcpy(client_hello + offset, cookie_data, cookie_len);
        offset += cookie_len;
    }

    /* Connection ID (RFC 9146/9147): DTLS 1.3 only; zero-length = prepared but no CID requested */
    if(tls13_is_dtls(ctx)) {
        client_hello[offset++] = (TLS_EXTENSION_CONNECTION_ID >> 8) & 0xFF;
        client_hello[offset++] = TLS_EXTENSION_CONNECTION_ID & 0xFF;
        client_hello[offset++] = 0x00;
        client_hello[offset++] = 0x01;  /* extension data length */
        client_hello[offset++] = 0x00;  /* ConnectionId: zero-length cid */
    }

    if(offer_psk) {
        uint8_t modes_len = include_key_share ? 2 : 1;
        client_hello[offset++] = (TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES >> 8) & 0xFF;
        client_hello[offset++] = TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES & 0xFF;
        client_hello[offset++] = 0x00;
        client_hello[offset++] = (uint8_t)(1 + modes_len);
        client_hello[offset++] = modes_len;
        if(include_key_share) {
            client_hello[offset++] = TLS13_PSK_KE_MODE_PSK_DHE_KE;
            client_hello[offset++] = TLS13_PSK_KE_MODE_PSK_KE;
        } else {
            client_hello[offset++] = TLS13_PSK_KE_MODE_PSK_KE;
        }

        /* early_data (RFC 8446 4.2.10): offer 0-RTT when resuming */
        if(offer_resumption) {
            client_hello[offset++] = (TLS_EXTENSION_EARLY_DATA >> 8) & 0xFF;
            client_hello[offset++] = TLS_EXTENSION_EARLY_DATA & 0xFF;
            client_hello[offset++] = 0x00;
            client_hello[offset++] = 0x00;
        }

        /* pre_shared_key must be the last ClientHello extension */
        client_hello[offset++] = (TLS_EXTENSION_PRE_SHARED_KEY >> 8) & 0xFF;
        client_hello[offset++] = TLS_EXTENSION_PRE_SHARED_KEY & 0xFF;
        {
            uint32_t psk_ext_len_pos = offset;
            uint32_t psk_ext_start;
            uint16_t psk_identities_len = 0;
            uint16_t psk_binders_len;
            uint32_t identities_start;

            client_hello[offset++] = 0x00;
            client_hello[offset++] = 0x00;
            psk_ext_start = offset;

            identities_start = offset + 2;
            if(offer_resumption) {
                psk_identities_len += (uint16_t)(2 + ctx->ticket_identity_len + 4);
            }
            if(offer_external_psk) {
                psk_identities_len += (uint16_t)(2 + ctx->psk_identity_len + 4);
            }
            client_hello[offset++] = (uint8_t)(psk_identities_len >> 8);
            client_hello[offset++] = (uint8_t)(psk_identities_len & 0xFF);

            if(offer_resumption) {
                client_hello[offset++] = (uint8_t)(ctx->ticket_identity_len >> 8);
                client_hello[offset++] = (uint8_t)(ctx->ticket_identity_len & 0xFF);
                memcpy(client_hello + offset, ctx->ticket_identity, ctx->ticket_identity_len);
                offset += ctx->ticket_identity_len;
                client_hello[offset++] = 0x00;
                client_hello[offset++] = 0x00;
                client_hello[offset++] = 0x00;
                client_hello[offset++] = 0x00;
            }
            if(offer_external_psk) {
                client_hello[offset++] = (uint8_t)(ctx->psk_identity_len >> 8);
                client_hello[offset++] = (uint8_t)(ctx->psk_identity_len & 0xFF);
                memcpy(client_hello + offset, ctx->psk_identity, ctx->psk_identity_len);
                offset += ctx->psk_identity_len;
                client_hello[offset++] = 0x00;
                client_hello[offset++] = 0x00;
                client_hello[offset++] = 0x00;
                client_hello[offset++] = 0x00;
            }

            psk_binder_len = (uint16_t)psk_hash_len;
            psk_binders_len = (uint16_t)((offer_resumption ? (1U + psk_binder_len) : 0) + (offer_external_psk ? (1U + psk_binder_len) : 0));
            client_hello[offset++] = (uint8_t)(psk_binders_len >> 8);
            client_hello[offset++] = (uint8_t)(psk_binders_len & 0xFF);
            if(offer_resumption) {
                client_hello[offset++] = (uint8_t)psk_binder_len;
                resumption_binder_offset = offset;
                memset(client_hello + offset, 0, psk_binder_len);
                offset += psk_binder_len;
            }
            if(offer_external_psk) {
                client_hello[offset++] = (uint8_t)psk_binder_len;
                external_binder_offset = offset;
                memset(client_hello + offset, 0, psk_binder_len);
                offset += psk_binder_len;
            }

            {
                uint16_t psk_ext_len = (uint16_t)(offset - psk_ext_start);
                client_hello[psk_ext_len_pos] = (uint8_t)(psk_ext_len >> 8);
                client_hello[psk_ext_len_pos + 1] = (uint8_t)(psk_ext_len & 0xFF);
            }
            (void)identities_start;
        }
    }

    /* Update extensions length */
    uint32_t extensions_len32 = offset - extensions_start - 2;
    if(extensions_len32 > UINT16_MAX) {
        if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    uint16_t extensions_len = (uint16_t)extensions_len32;
    client_hello[extensions_start] = (extensions_len >> 8) & 0xFF;
    client_hello[extensions_start + 1] = extensions_len & 0xFF;
    
    /* Update handshake noxtls_message length */
    uint32_t handshake_len = offset - 4;
    client_hello[1] = (handshake_len >> 16) & 0xFF;
    client_hello[2] = (handshake_len >> 8) & 0xFF;
    client_hello[3] = handshake_len & 0xFF;
    if(offer_psk && psk_binder_len > 0) {
        uint8_t binder[64];
        noxtls_return_t psk_rc;
        if(offer_resumption && resumption_binder_offset > 0) {
            psk_rc = tls13_psk_compute_resumption_binder(psk_hash_algo,
                                                         ctx->resumption_psk, ctx->resumption_psk_len,
                                                         ctx->ticket_nonce, ctx->ticket_nonce_len,
                                                         client_hello, offset,
                                                         resumption_binder_offset, psk_binder_len,
                                                         binder,
                                                         binder_transcript_prefix,
                                                         binder_transcript_prefix_len);
            if(psk_rc != NOXTLS_RETURN_SUCCESS) {
                tls13_connect_log_fail(ctx, "send_client_hello/resumption_binder", psk_rc);
                if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return psk_rc;
            }
            memcpy(client_hello + resumption_binder_offset, binder, psk_binder_len);
        }
        if(offer_external_psk && external_binder_offset > 0) {
            const char *psk_fail_step = NULL;
            psk_rc = tls13_psk_compute_external_binder(psk_hash_algo,
                                                       ctx->psk_key, ctx->psk_key_len,
                                                       client_hello, offset,
                                                       external_binder_offset, psk_binder_len,
                                                       binder,
                                                       binder_transcript_prefix,
                                                       binder_transcript_prefix_len,
                                                       &psk_fail_step);
            if(psk_rc != NOXTLS_RETURN_SUCCESS) {
                tls13_connect_log_fail_detail(ctx, "send_client_hello/external_binder", psk_fail_step, psk_rc);
                if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return psk_rc;
            }
            if(binder_transcript_prefix_len > 0U) {
                uint8_t prefix_hash[64];
                uint32_t prefix_hash_len = sizeof(prefix_hash);
                if(tls13_hash_messages(psk_hash_algo,
                                       binder_transcript_prefix,
                                       binder_transcript_prefix_len,
                                       prefix_hash,
                                       &prefix_hash_len) == NOXTLS_RETURN_SUCCESS) {
                    noxtls_debug_printf("[TLS13_DEBUG] send_client_hello: external binder prefix_hash=%02X%02X%02X%02X len=%lu binder=%02X%02X%02X%02X\n",
                                        prefix_hash[0],
                                        prefix_hash[1],
                                        prefix_hash[2],
                                        prefix_hash[3],
                                        (unsigned long)binder_transcript_prefix_len,
                                        binder[0],
                                        binder[1],
                                        binder[2],
                                        binder[3]);
                }
            }
            memcpy(client_hello + external_binder_offset, binder, psk_binder_len);
        }
    }
    noxtls_debug_printf("[TLS13_DEBUG] client_hello: len=%u\n", handshake_len + 4);
    
    /* Append to handshake transcript */
    {
        noxtls_return_t append_rc = tls13_append_handshake_message(ctx, client_hello, offset);
        if(append_rc != NOXTLS_RETURN_SUCCESS) {
            tls13_connect_log_fail(ctx, "send_client_hello/append_transcript", append_rc);
            if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return append_rc;
        }
    }

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
        noxtls_return_t send_rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, client_hello, offset);
        if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        if(send_rc == NOXTLS_RETURN_SUCCESS) {
            NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_HANDSHAKE, NOXSIGHT_SEVERITY_INFO,
                            NOXTLS_EVT_CLIENT_HELLO_SENT, offset, 0U);
        } else {
            tls13_connect_log_fail(ctx, "send_client_hello/send_record", send_rc);
            NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_IO, NOXSIGHT_SEVERITY_ERROR,
                            NOXTLS_EVT_INTERNAL_ERROR, NOXTLS_EVT_CLIENT_HELLO_SENT, send_rc);
        }
        return send_rc;
    }
}

/**
 * @brief Client: receive and process ServerHello (cipher suite, key share, transcript update).
 * @param[in,out] ctx Client context; derives handshake keys on success.
 * @return `NOXTLS_RETURN_SUCCESS` on success; I/O, parse, or key-exchange error otherwise.
 */
noxtls_return_t noxtls_tls13_recv_server_hello(tls13_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    int is_hrr = 0;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    for(;;) {
        rc = noxtls_tls_recv_record(&ctx->base.base, &record);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_IO, NOXSIGHT_SEVERITY_ERROR,
                            NOXTLS_EVT_INTERNAL_ERROR, NOXTLS_EVT_SERVER_HELLO_RECV, rc);
            return rc;
        }
        if(record.data == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        if(record.type == TLS_RECORD_CHANGE_CIPHER_SPEC) {
            noxtls_return_t ccs_rc = tls13_handle_peer_compat_ccs(ctx, &record);
            free(record.data);
            if(ccs_rc != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_TLS_ERROR;
            }
            continue;
        }
        if(record.type == TLS_RECORD_ACK && tls13_is_dtls(ctx)) {
            if(record.length > 0 && record.data != NULL) {
                tls13_dtls_handle_ack(ctx, record.data, record.length);
            }
            free(record.data);
            continue;
        }
        if(record.type == TLS_RECORD_ALERT) {
            free(record.data);
            ctx->peer_alert_received = 1;
            ctx->base.base.state = TLS_STATE_CLOSED;
            return NOXTLS_RETURN_FAILED;
        }
        break;
    }
    
    noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: record type=%u len=%u\n", record.type, record.length);
    if(record.type != TLS_RECORD_HANDSHAKE || record.data == NULL || record.length < 42) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: hs_type=0x%02X\n", record.data[0]);
    if(record.data[0] != TLS_HANDSHAKE_SERVER_HELLO) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    {
        uint32_t hs_len = ((uint32_t)record.data[1] << 16) | ((uint32_t)record.data[2] << 8) | record.data[3];
        noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: hs_len=%u\n", hs_len);
    }
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
    if(offset + 2 + TLS_RANDOM_SIZE + 1 > record.length) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    offset += 2; /* legacy_version */
    memcpy(ctx->server_random, record.data + offset, TLS_RANDOM_SIZE);
    noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: server_random[0..3]=%02X%02X%02X%02X\n",
                          ctx->server_random[0], ctx->server_random[1], ctx->server_random[2], ctx->server_random[3]);
    {
        static const uint8_t hrr_random[TLS_RANDOM_SIZE] = {
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
        };
        if(memcmp(ctx->server_random, hrr_random, sizeof(hrr_random)) == 0) {
            noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: detected HelloRetryRequest (HRR)\n");
            if(tls13_is_dtls(ctx)) {
                is_hrr = 1;
                ctx->received_hrr = 1U;
            }
        }
    }
    offset += TLS_RANDOM_SIZE;

    uint8_t session_id_len = record.data[offset++];
    if(offset + session_id_len + 2 + 1 + 2 > record.length) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    offset += session_id_len;

    ctx->cipher_suite = (record.data[offset] << 8) | record.data[offset + 1];
    noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: cipher_suite=0x%04X\n", ctx->cipher_suite);
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_HANDSHAKE, NOXSIGHT_SEVERITY_INFO,
                    NOXTLS_EVT_SERVER_HELLO_RECV, ctx->cipher_suite, record.length);
    offset += 2;

    offset += 1; /* legacy compression method */

    if(offset + 2 > record.length) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }

    /* Parse extensions */
    noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: extensions_len=%u\n", (unsigned)(record.length - offset));
    if(tls13_parse_raw_extension_list(record.data + offset, record.length - offset, &ctx->server_extensions) != NOXTLS_RETURN_SUCCESS) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    if(is_hrr) {
        noxtls_hash_algos_t hash_algo;
        uint32_t hash_len;
        uint32_t key_len;
        tls_extension_t *ext_keyshare = NULL;
        if(tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len) != NOXTLS_RETURN_SUCCESS) {
            free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        if(tls13_is_dtls(ctx) && offset + 2U <= record.length) {
            uint32_t ext_scan = offset + 2U;
            uint32_t ext_end = ext_scan + (((uint32_t)record.data[offset] << 8) | (uint32_t)record.data[offset + 1U]);

            if(ext_end <= record.length) {
                while(ext_scan + 4U <= ext_end) {
                    uint16_t ext_type = (uint16_t)(((uint16_t)record.data[ext_scan] << 8) |
                                                   (uint16_t)record.data[ext_scan + 1U]);
                    uint16_t ext_len = (uint16_t)(((uint16_t)record.data[ext_scan + 2U] << 8) |
                                                  (uint16_t)record.data[ext_scan + 3U]);
                    ext_scan += 4U;
                    if(ext_scan + ext_len > ext_end) {
                        break;
                    }
                    if(ext_type == TLS_EXTENSION_COOKIE && ext_len >= 2U) {
                        uint16_t ext_cookie_len = (uint16_t)(((uint16_t)record.data[ext_scan] << 8) |
                                                             (uint16_t)record.data[ext_scan + 1U]);
                        if(ext_cookie_len == ext_len - 2U) {
                            noxtls_return_t cookie_rc = tls13_dtls_store_hrr_cookie(ctx,
                                                                                     record.data + ext_scan + 2U,
                                                                                     ext_cookie_len);
                            if(cookie_rc != NOXTLS_RETURN_SUCCESS) {
                                free(record.data);
                                return cookie_rc;
                            }
                            noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: stored hrr cookie_len=%u\n",
                                                (unsigned)ctx->base.hrr_cookie_len);
                        }
                        break;
                    }
                    ext_scan += ext_len;
                }
            }
        }
        if(noxtls_tls_find_extension(&ctx->server_extensions, TLS_EXTENSION_KEY_SHARE, &ext_keyshare) == NOXTLS_RETURN_SUCCESS) {
            if(ext_keyshare != NULL && ext_keyshare->length >= 2) {
                uint16_t group = (ext_keyshare->data[0] << 8) | ext_keyshare->data[1];
                tls_ecdhe_context_t *ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
                if(ecdhe_ctx == NULL || ecdhe_ctx->named_group != group) {
                    if(ecdhe_ctx) {
                        noxtls_tls_ecdhe_context_free(ecdhe_ctx);
                        free(ecdhe_ctx);
                    }
                    ecdhe_ctx = (tls_ecdhe_context_t*)malloc(sizeof(tls_ecdhe_context_t));
                    if(ecdhe_ctx == NULL) {
                        free(record.data);
                        return NOXTLS_RETURN_FAILED;
                    }
                    if(noxtls_tls_ecdhe_context_init(ecdhe_ctx, group) != NOXTLS_RETURN_SUCCESS ||
                       noxtls_tls_ecdhe_generate_ephemeral_key(ecdhe_ctx) != NOXTLS_RETURN_SUCCESS) {
                        noxtls_tls_ecdhe_context_free(ecdhe_ctx);
                        free(ecdhe_ctx);
                        free(record.data);
                        return NOXTLS_RETURN_FAILED;
                    }
                    ctx->ecdhe_ctx = ecdhe_ctx;
                }
            }
        }
        if(tls13_reset_transcript_for_hrr(ctx, hash_algo, hash_len) != NOXTLS_RETURN_SUCCESS) {
            free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        tls13_append_handshake_message(ctx, record.data, record.length);
        free(record.data);
        rc = noxtls_tls13_send_client_hello(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        return noxtls_tls13_recv_server_hello(ctx);
    }

    ctx->received_hrr = 0U;

    tls_extension_t *ext = NULL;
    {
        int downgrade_to_tls12 = 0;
        if(noxtls_tls_find_extension(&ctx->server_extensions, TLS_EXTENSION_SUPPORTED_VERSIONS, &ext) == NOXTLS_RETURN_SUCCESS) {
            if(ext == NULL || ext->length != 2 || ext->data == NULL) {
                free(record.data);
                noxtls_tls_extensions_free(&ctx->server_extensions);
                memset(&ctx->server_extensions, 0, sizeof(ctx->server_extensions));
                return NOXTLS_RETURN_FAILED;
            }
            {
                uint16_t negotiated = (ext->data[0] << 8) | ext->data[1];
                noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: supported_versions=0x%04X\n", negotiated);
                if((tls13_is_dtls(ctx) && negotiated == DTLS_VERSION_1_3) ||
                   (!tls13_is_dtls(ctx) && negotiated == TLS_VERSION_1_3)) {
                    /* continue as TLS 1.3 */
                } else if(!tls13_is_dtls(ctx) && negotiated == TLS_VERSION_1_2) {
                    downgrade_to_tls12 = 1;
                } else {
                    free(record.data);
                    noxtls_tls_extensions_free(&ctx->server_extensions);
                    memset(&ctx->server_extensions, 0, sizeof(ctx->server_extensions));
                    return NOXTLS_RETURN_FAILED;
                }
            }
        } else {
            /* Legacy TLS 1.2 ServerHello has no supported_versions extension */
            noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: supported_versions not found (TLS 1.2 downgrade)\n");
            downgrade_to_tls12 = 1;
        }

        if(downgrade_to_tls12) {
            if(ctx->cipher_suite >= 0x1300u && ctx->cipher_suite <= 0x13FFu) {
                free(record.data);
                noxtls_tls_extensions_free(&ctx->server_extensions);
                memset(&ctx->server_extensions, 0, sizeof(ctx->server_extensions));
                return NOXTLS_RETURN_FAILED;
            }
            if(ctx->client_tls12_downgrade_server_hello != NULL) {
                free(ctx->client_tls12_downgrade_server_hello);
                ctx->client_tls12_downgrade_server_hello = NULL;
                ctx->client_tls12_downgrade_server_hello_len = 0;
            }
            ctx->client_tls12_downgrade_server_hello = record.data;
            ctx->client_tls12_downgrade_server_hello_len = record.length;
            record.data = NULL;
            noxtls_tls_extensions_free(&ctx->server_extensions);
            memset(&ctx->server_extensions, 0, sizeof(ctx->server_extensions));
            return NOXTLS_RETURN_NEGOTIATED_TLS12;
        }
    }

    /* Append only after ServerHello is confirmed TLS 1.3 (avoids corrupt transcript on early reject). */
    tls13_append_handshake_message(ctx, record.data, record.length);

    /* Connection ID (RFC 9147): store server's CID for use in record header when sending */
    {
        tls_extension_t *ext_cid = NULL;
        if(tls13_is_dtls(ctx) &&
           noxtls_tls_find_extension(&ctx->server_extensions, TLS_EXTENSION_CONNECTION_ID, &ext_cid) == NOXTLS_RETURN_SUCCESS &&
           ext_cid != NULL && ext_cid->length >= 1 && ext_cid->data != NULL) {
            uint8_t cid_len = ext_cid->data[0];
            if(cid_len > 0 && cid_len <= 32 && ext_cid->length >= 1U + cid_len) {
                ctx->peer_connection_id_len = cid_len;
                memcpy(ctx->peer_connection_id, ext_cid->data + 1, cid_len);
            }
        }
    }

    {
        int have_key_share = 0;
        int server_selected_psk = 0;
        int offered_resumption = 0;
        int offered_external_psk = 0;
        uint16_t selected_identity;
        const uint8_t *shared_secret = NULL;
        uint32_t shared_secret_len = 0;

        offered_resumption = (ctx->ticket_stored && ctx->ticket_identity_len > 0 && ctx->resumption_psk_len > 0);
        offered_external_psk = (ctx->psk_configured && ctx->psk_identity_len > 0 && ctx->psk_key_len > 0);

        if(noxtls_tls_find_extension(&ctx->server_extensions, TLS_EXTENSION_PRE_SHARED_KEY, &ext) == NOXTLS_RETURN_SUCCESS) {
            if(ext == NULL || ext->data == NULL || ext->length != 2) {
                free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            selected_identity = tls13_read_uint16(ext->data);
            if(offered_resumption && selected_identity == 0) {
                memset(ctx->psk_key, 0, sizeof(ctx->psk_key));
                memcpy(ctx->psk_key, ctx->resumption_psk, ctx->resumption_psk_len);
                ctx->psk_key_len = ctx->resumption_psk_len;
            } else {
                const uint16_t external_identity_index = offered_resumption ? 1U : 0U;
                if(!offered_external_psk || selected_identity != external_identity_index) {
                    free(record.data);
                    return NOXTLS_RETURN_FAILED;
                }
            }
            server_selected_psk = 1;
            ctx->psk_in_use = 1;
            ctx->psk_selected_identity = selected_identity;
        }

        if(noxtls_tls_find_extension(&ctx->server_extensions, TLS_EXTENSION_KEY_SHARE, &ext) == NOXTLS_RETURN_SUCCESS) {
            uint16_t group;
            uint16_t key_len;
            have_key_share = 1;
            if(ext == NULL || ext->length < 4 || ext->data == NULL) {
                free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            group = (uint16_t)((ext->data[0] << 8) | ext->data[1]);
            key_len = (uint16_t)((ext->data[2] << 8) | ext->data[3]);
            noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: key_share group=0x%04X len=%u\n", group, key_len);
            if(ext->length >= 8) {
                noxtls_debug_printf("[TLS13_DEBUG] server_key_share: key[0..3]=%02X%02X%02X%02X\n",
                                      ext->data[4], ext->data[5], ext->data[6], ext->data[7]);
            }
            if(4 + key_len > ext->length) {
                free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            tls13_free_server_key_share(ctx);
            if(key_len <= sizeof(ctx->server_key_share_inline_buf)) {
                memset(&ctx->server_key_share_inline, 0, sizeof(ctx->server_key_share_inline));
                memset(ctx->server_key_share_inline_buf, 0, sizeof(ctx->server_key_share_inline_buf));
                ctx->server_key_share = &ctx->server_key_share_inline;
                ctx->server_key_share->key_exchange = ctx->server_key_share_inline_buf;
            } else {
                ctx->server_key_share = (tls13_key_share_entry_t*)malloc(sizeof(tls13_key_share_entry_t));
                if(ctx->server_key_share == NULL) {
                    free(record.data);
                    return NOXTLS_RETURN_FAILED;
                }
                memset(ctx->server_key_share, 0, sizeof(*ctx->server_key_share));
                ctx->server_key_share->key_exchange = (uint8_t*)malloc(key_len);
                if(ctx->server_key_share->key_exchange == NULL) {
                    free(ctx->server_key_share);
                    ctx->server_key_share = NULL;
                    free(record.data);
                    return NOXTLS_RETURN_FAILED;
                }
            }
            ctx->server_key_share->group = group;
            ctx->server_key_share->key_exchange_len = key_len;
            memcpy(ctx->server_key_share->key_exchange, ext->data + 4, key_len);
            ctx->selected_kex_group = group;
            ctx->selected_kex_is_hybrid = tls13_group_is_hybrid(group) ? 1U : 0U;
            ctx->selected_mlkem_param = tls13_group_mlkem_param(group);
        }

        free(record.data);

        if(have_key_share) {
            tls_ecdhe_context_t *ecdhe_ctx;
            if(ctx->server_key_share == NULL) {
                return NOXTLS_RETURN_FAILED;
            }
            if(!tls13_group_is_mlkem(ctx->server_key_share->group) &&
               !tls13_group_is_hybrid(ctx->server_key_share->group)) {
                if(ctx->ecdhe_ctx == NULL) {
                    return NOXTLS_RETURN_FAILED;
                }
                ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
                rc = noxtls_tls13_process_server_key_share(ctx, ecdhe_ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: process_key_share rc=%d\n", rc);
                    return rc;
                }
                if(ecdhe_ctx->shared_secret == NULL || ecdhe_ctx->shared_secret_len == 0) {
                    return NOXTLS_RETURN_FAILED;
                }
                shared_secret = ecdhe_ctx->shared_secret;
                shared_secret_len = ecdhe_ctx->shared_secret_len;
            } else {
#if NOXTLS_FEATURE_ML_KEM
                noxtls_mlkem_param_t p = tls13_group_mlkem_param(ctx->server_key_share->group);
                uint8_t pq_ss[NOXTLS_MLKEM_SHARED_SECRET_LEN];
                if(p == 0) {
                    return NOXTLS_RETURN_FAILED;
                }
                if(tls13_group_is_mlkem(ctx->server_key_share->group)) {
                    if(noxtls_mlkem_decaps(p, ctx->mlkem_client_public_key, ctx->mlkem_client_secret_key,
                                           ctx->server_key_share->key_exchange, pq_ss) != NOXTLS_RETURN_SUCCESS) {
                        return NOXTLS_RETURN_FAILED;
                    }
                    memcpy(ctx->hybrid_shared_secret, pq_ss, NOXTLS_MLKEM_SHARED_SECRET_LEN);
                    ctx->hybrid_shared_secret_len = NOXTLS_MLKEM_SHARED_SECRET_LEN;
                    shared_secret = ctx->hybrid_shared_secret;
                    shared_secret_len = ctx->hybrid_shared_secret_len;
                } else {
                    uint16_t x_len;
                    uint16_t ct_len;
                    uint32_t ct_expected_len = noxtls_mlkem_ciphertext_len(p);
                    const uint8_t *x_pub;
                    const uint8_t *ct;
                    if(ctx->ecdhe_ctx == NULL) {
                        return NOXTLS_RETURN_FAILED;
                    }
                    ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
                    if(ctx->server_key_share->group == TLS_NAMED_GROUP_X25519_MLKEM768) {
                        if(ct_expected_len == 0 || ctx->server_key_share->key_exchange_len != (uint16_t)(NOXTLS_X25519_KEY_SIZE + ct_expected_len)) {
                            return NOXTLS_RETURN_FAILED;
                        }
                        x_len = NOXTLS_X25519_KEY_SIZE;
                        ct_len = (uint16_t)ct_expected_len;
                        ct = ctx->server_key_share->key_exchange;
                        x_pub = ctx->server_key_share->key_exchange + ct_expected_len;
                    } else {
                        if(ctx->server_key_share->key_exchange_len < 4U) {
                            return NOXTLS_RETURN_FAILED;
                        }
                        x_len = tls13_read_uint16(ctx->server_key_share->key_exchange);
                        if(ctx->server_key_share->key_exchange_len < 2U + x_len + 2U) {
                            return NOXTLS_RETURN_FAILED;
                        }
                        x_pub = ctx->server_key_share->key_exchange + 2U;
                        ct_len = tls13_read_uint16(ctx->server_key_share->key_exchange + 2U + x_len);
                        if(ctx->server_key_share->key_exchange_len < 2U + x_len + 2U + ct_len || x_len != NOXTLS_X25519_KEY_SIZE) {
                            return NOXTLS_RETURN_FAILED;
                        }
                        ct = ctx->server_key_share->key_exchange + 2U + x_len + 2U;
                    }
                    if(noxtls_tls_ecdhe_compute_shared_secret_x25519(ecdhe_ctx, x_pub) != NOXTLS_RETURN_SUCCESS) {
                        return NOXTLS_RETURN_FAILED;
                    }
                    if(noxtls_mlkem_decaps(p, ctx->mlkem_client_public_key, ctx->mlkem_client_secret_key, ct, pq_ss) != NOXTLS_RETURN_SUCCESS) {
                        return NOXTLS_RETURN_FAILED;
                    }
                    if(tls13_combine_hybrid_secrets(ctx, ecdhe_ctx->shared_secret, ecdhe_ctx->shared_secret_len,
                                                   pq_ss, NOXTLS_MLKEM_SHARED_SECRET_LEN) != NOXTLS_RETURN_SUCCESS) {
                        return NOXTLS_RETURN_FAILED;
                    }
                    shared_secret = ctx->hybrid_shared_secret;
                    shared_secret_len = ctx->hybrid_shared_secret_len;
                }
#else
                return NOXTLS_RETURN_FAILED;
#endif
            }
            ctx->psk_use_ecdhe = server_selected_psk ? 1 : 0;
        } else if(server_selected_psk) {
            ctx->psk_use_ecdhe = 0;
        } else {
            noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: neither key_share nor psk selected\n");
            return NOXTLS_RETURN_FAILED;
        }

        rc = tls13_derive_handshake_keys(ctx, shared_secret, shared_secret_len);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: derive_handshake_keys rc=%d\n", rc);
    }
    return rc;
}

/**
 * @brief Client: receive EncryptedExtensions handshake message.
 * @param[in,out] ctx Client context with handshake traffic keys active.
 * @return `NOXTLS_RETURN_SUCCESS` on success; receive or parse error otherwise.
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
        if(ext_len > 0 && 6U + ext_len <= msg_len) {
            noxtls_tls_parse_extensions(msg + 6, ext_len, &ctx->server_extensions);
            /* If server sent early_data extension, 0-RTT was accepted */
            {
                tls_extension_t *ext_early = NULL;
                if(noxtls_tls_find_extension(&ctx->server_extensions, TLS_EXTENSION_EARLY_DATA, &ext_early) == NOXTLS_RETURN_SUCCESS &&
                   ext_early != NULL) {
                    ctx->early_data_accepted = 1;
                    if(ext_early->length >= 4 && ext_early->data != NULL) {
                        ctx->max_early_data_size = ((uint32_t)ext_early->data[0] << 24) | ((uint32_t)ext_early->data[1] << 16) |
                                                   ((uint32_t)ext_early->data[2] << 8) | ext_early->data[3];
                    }
                }
            }
            /* RFC 8449: record_size_limit = max plaintext we may send to server */
            {
                tls_extension_t *ext_rsl = NULL;
                if(noxtls_tls_find_extension(&ctx->server_extensions, TLS_EXTENSION_RECORD_SIZE_LIMIT, &ext_rsl) == NOXTLS_RETURN_SUCCESS &&
                   ext_rsl != NULL && ext_rsl->data != NULL && ext_rsl->length >= 2) {
                    ctx->record_size_limit_send = (uint16_t)((ext_rsl->data[0] << 8) | ext_rsl->data[1]);
                }
            }
        }
    }

    free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Client: receive CertificateRequest or stash the next message if it is Certificate.
 *
 * Call after EncryptedExtensions. Parses CertificateRequest and sets `client_auth_requested`, or
 * stores a pending server Certificate for `noxtls_tls13_recv_certificate`.
 *
 * @param[in,out] ctx Client context.
 * @return `NOXTLS_RETURN_SUCCESS` on success; handshake ordering or I/O error otherwise.
 */
noxtls_return_t noxtls_tls13_recv_certificate_request(tls13_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->pending_handshake_msg) {
        free(ctx->pending_handshake_msg);
        ctx->pending_handshake_msg = NULL;
        ctx->pending_handshake_len = 0;
    }
    ctx->client_auth_requested = 0;
    ctx->cert_request_context_len = 0;

    rc = tls13_recv_handshake_message(ctx, &msg, &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(msg_len < 4) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }

    if(msg[0] == TLS_HANDSHAKE_CERTIFICATE_REQUEST) {
        /* Parse CertificateRequest: certificate_request_context<0..255>, Extension extensions<2..2^16-1> */
        uint32_t off = 4;
        if(off + 1 > msg_len) {
            free(msg);
            return NOXTLS_RETURN_FAILED;
        }
        uint8_t ctx_len = msg[off++];
        if(ctx_len > sizeof(ctx->cert_request_context)) {
            ctx_len = sizeof(ctx->cert_request_context);
        }
        if(off + ctx_len + 2 > msg_len) {
            free(msg);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(ctx->cert_request_context, msg + off, ctx_len);
        ctx->cert_request_context_len = ctx_len;
        tls13_append_handshake_message(ctx, msg, msg_len);
        ctx->client_auth_requested = 1;
        free(msg);
        return NOXTLS_RETURN_SUCCESS;
    }

    if(msg[0] == TLS_HANDSHAKE_CERTIFICATE) {
        /* Server did not send CertificateRequest; next noxtls_message is server Certificate. Push back for recv_certificate. */
        ctx->pending_handshake_msg = msg;
        ctx->pending_handshake_len = msg_len;
        return NOXTLS_RETURN_SUCCESS;
    }

    if(msg[0] == TLS_HANDSHAKE_FINISHED) {
        /* PSK-only handshake without client auth: after EncryptedExtensions, server can send Finished directly. */
        ctx->pending_handshake_msg = msg;
        ctx->pending_handshake_len = msg_len;
        return NOXTLS_RETURN_SUCCESS;
    }

    free(msg);
    return NOXTLS_RETURN_FAILED;
}

/**
 * @brief Client: receive and parse the server Certificate message.
 * @param[in,out] ctx Client context; stores DER chain for verification.
 * @return `NOXTLS_RETURN_SUCCESS` on success; receive, parse, or memory error otherwise.
 */
noxtls_return_t noxtls_tls13_recv_certificate(tls13_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    uint32_t cert_list_len;
    uint32_t cert_len;
    uint32_t cert_list_start;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(ctx->pending_handshake_msg != NULL) {
        msg = ctx->pending_handshake_msg;
        msg_len = ctx->pending_handshake_len;
        ctx->pending_handshake_msg = NULL;
        ctx->pending_handshake_len = 0;
    } else {
        rc = tls13_recv_handshake_message(ctx, &msg, &msg_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    if(msg_len < 8 || msg[0] != TLS_HANDSHAKE_CERTIFICATE) {
        free(msg);
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_CERT_PARSE_FAIL, msg_len, 0U);
        return NOXTLS_RETURN_FAILED;
    }

    /* Append to transcript */
    tls13_append_handshake_message(ctx, msg, msg_len);

    /* Parse Certificate noxtls_message (TLS 1.3 format); need at least 4 bytes handshake header + 1 byte cert_request_context_len */
    uint32_t offset = 4;
    uint8_t cert_request_context_len = msg[offset++];
    if(offset + cert_request_context_len + 3 > msg_len) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    offset += cert_request_context_len;

    cert_list_len = (msg[offset] << 16) | (msg[offset + 1] << 8) | msg[offset + 2];
    offset += 3;
    cert_list_start = offset;
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
    offset += cert_len;

    if(offset + 2U > msg_len) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    {
        uint16_t leaf_ext_len = ((uint16_t)msg[offset] << 8) | (uint16_t)msg[offset + 1];
        offset += 2U;
        if(offset + leaf_ext_len > msg_len) {
            free(msg);
            return NOXTLS_RETURN_FAILED;
        }
        offset += leaf_ext_len;
    }

    if(ctx->server_cert_parsed) {
        noxtls_x509_certificate_free((x509_certificate_t*)ctx->server_cert_parsed);
        free(ctx->server_cert_parsed);
        ctx->server_cert_parsed = NULL;
    }

    x509_certificate_t *parsed_cert = (x509_certificate_t*)malloc(sizeof(x509_certificate_t));
    if(parsed_cert) {
        x509_certificate_chain_t presented_chain;
        uint32_t cert_list_end = cert_list_start + cert_list_len;

        if(noxtls_x509_certificate_chain_init(&presented_chain) != NOXTLS_RETURN_SUCCESS) {
            free(parsed_cert);
            free(msg);
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_x509_certificate_init(parsed_cert);
        noxtls_return_t parse_rc = noxtls_x509_certificate_parse_der(parsed_cert, ctx->server_cert, ctx->server_cert_len);
        if(parse_rc == NOXTLS_RETURN_SUCCESS) {
            ctx->server_cert_parsed = parsed_cert;

            while(offset + 3U <= cert_list_end) {
                uint32_t issuer_len = ((uint32_t)msg[offset] << 16) |
                                      ((uint32_t)msg[offset + 1] << 8) |
                                      (uint32_t)msg[offset + 2];
                x509_certificate_t issuer_cert;
                uint16_t issuer_ext_len;
                offset += 3U;
                if(issuer_len == 0 || offset + issuer_len + 2U > cert_list_end) {
                    noxtls_x509_certificate_chain_free(&presented_chain);
                    noxtls_x509_certificate_free(parsed_cert);
                    free(parsed_cert);
                    ctx->server_cert_parsed = NULL;
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }

                noxtls_x509_certificate_init(&issuer_cert);
                rc = noxtls_x509_certificate_parse_der(&issuer_cert, msg + offset, issuer_len);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_x509_certificate_free(&issuer_cert);
                    noxtls_x509_certificate_chain_free(&presented_chain);
                    noxtls_x509_certificate_free(parsed_cert);
                    free(parsed_cert);
                    ctx->server_cert_parsed = NULL;
                    free(msg);
                    return rc;
                }

                rc = noxtls_x509_certificate_chain_add(&presented_chain, &issuer_cert);
                noxtls_x509_certificate_free(&issuer_cert);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_x509_certificate_chain_free(&presented_chain);
                    noxtls_x509_certificate_free(parsed_cert);
                    free(parsed_cert);
                    ctx->server_cert_parsed = NULL;
                    free(msg);
                    return rc;
                }
                offset += issuer_len;
                issuer_ext_len = ((uint16_t)msg[offset] << 8) | (uint16_t)msg[offset + 1];
                offset += 2U;
                if(offset + issuer_ext_len > cert_list_end) {
                    noxtls_x509_certificate_chain_free(&presented_chain);
                    noxtls_x509_certificate_free(parsed_cert);
                    free(parsed_cert);
                    ctx->server_cert_parsed = NULL;
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }
                offset += issuer_ext_len;
            }

            if(offset != cert_list_end) {
                noxtls_x509_certificate_chain_free(&presented_chain);
                noxtls_x509_certificate_free(parsed_cert);
                free(parsed_cert);
                ctx->server_cert_parsed = NULL;
                free(msg);
                return NOXTLS_RETURN_FAILED;
            }

            rc = noxtls_x509_verify_server_cert_trust_ex((x509_certificate_t*)ctx->server_cert_parsed,
                                                         &presented_chain,
                                                         ctx->verify_crl,
                                                         NULL);
            noxtls_x509_certificate_chain_free(&presented_chain);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_x509_certificate_free(parsed_cert);
                free(parsed_cert);
                ctx->server_cert_parsed = NULL;
                free(msg);
                return rc;
            }
        } else {
            NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                            NOXTLS_EVT_CERT_PARSE_FAIL, ctx->server_cert_len, 1U);
            noxtls_x509_certificate_free(parsed_cert);
            free(parsed_cert);
            noxtls_x509_certificate_chain_free(&presented_chain);
            free(msg);
            return parse_rc;
        }
    } else {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }

    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_INFO,
                    NOXTLS_EVT_CERTIFICATE_RECV, ctx->server_cert_len, 0U);
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
                        NOXTLS_EVT_VERIFY_SIG_FAIL, 1U, msg_len);
        return NOXTLS_RETURN_FAILED;
    }

    if(msg_len < 8 || ctx->server_cert_parsed == NULL) {
        free(msg);
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_VERIFY_SIG_FAIL, 2U, msg_len);
        return NOXTLS_RETURN_FAILED;
    }

    /* Verify Certificate Verify signature before appending (signature is over transcript excluding this noxtls_message) */
    {
        uint16_t sig_scheme = (msg[4] << 8) | msg[5];
        uint16_t sig_len = (msg[6] << 8) | msg[7];
        /* Signed content per RFC 8446: 64*0x20 + "TLS 1.3, server CertificateVerify" + 0x00 + Hash */
        static const char ctx_str[] = "TLS 1.3, server CertificateVerify";
        uint8_t to_verify[64 + sizeof(ctx_str) + 1 + 64];
        uint32_t to_verify_len = 0;

        if(8U + sig_len != msg_len) {
            free(msg);
            return NOXTLS_RETURN_FAILED;
        }
        rc = tls13_build_certificate_verify_tosign(ctx, sig_scheme, ctx_str,
                                                   (uint32_t)(sizeof(ctx_str) - 1U),
                                                   to_verify, &to_verify_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(msg);
            return rc;
        }

        {
            x509_certificate_t *cert = (x509_certificate_t *)ctx->server_cert_parsed;
            if(sig_scheme == TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256) {
                uint32_t key_bytes;
                rsa_key_t rsa_key;
                rsa_key_size_t key_size;

                if(cert->rsa_modulus == NULL || cert->rsa_exponent == NULL) {
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }
                key_bytes = cert->rsa_modulus_len;
                if(key_bytes != 128 && key_bytes != 256 && key_bytes != 384 && key_bytes != 512) {
                    free(msg);
                    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                                    NOXTLS_EVT_VERIFY_SIG_FAIL, 2U, key_bytes);
                    return NOXTLS_RETURN_FAILED;
                }
                key_size = (key_bytes == 128) ? RSA_1024_BIT : (key_bytes == 256) ? RSA_2048_BIT :
                           (key_bytes == 384) ? RSA_3072_BIT : RSA_4096_BIT;
                rc = noxtls_rsa_key_init(&rsa_key, key_size);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    free(msg);
                    return rc;
                }
                memset(rsa_key.n, 0, rsa_key.key_bytes);
                memset(rsa_key.e, 0, rsa_key.key_bytes);
                memcpy(rsa_key.n, cert->rsa_modulus, cert->rsa_modulus_len);
                memcpy(rsa_key.e + rsa_key.key_bytes - cert->rsa_exponent_len,
                       cert->rsa_exponent, cert->rsa_exponent_len);
                rc = noxtls_rsa_verify_pss(&rsa_key, to_verify, to_verify_len, msg + 8, sig_len, NOXTLS_HASH_SHA_256);
                noxtls_rsa_key_free(&rsa_key);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    free(msg);
                    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                                    NOXTLS_EVT_VERIFY_SIG_FAIL, 3U, rc);
                    return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
                }
            } else if(sig_scheme == TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256 ||
                      sig_scheme == TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384) {
                void *pubkey;
                uint32_t key_type;
                ecc_key_t *ecc_key;
                ecdsa_signature_t ecdsa_sig;
                uint32_t coord_size;
                noxtls_hash_algos_t verify_hash;

                if(cert->ecc_public_key == NULL || cert->ecc_public_key_len == 0) {
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }
                coord_size = (sig_scheme == TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256) ? 32U : 48U;
                if(!tls13_ecdsa_sig_scheme_to_hash(sig_scheme, &verify_hash)) {
                    free(msg);
                    return NOXTLS_RETURN_INVALID_ALGORITHM;
                }

                pubkey = NULL;
                key_type = 0;
                rc = noxtls_x509_certificate_get_public_key(cert, &pubkey, &key_type);
                if(rc != NOXTLS_RETURN_SUCCESS || pubkey == NULL || key_type != 2) {
                    if(pubkey != NULL) {
                        free(pubkey);
                    }
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }
                ecc_key = (ecc_key_t *)pubkey;
                if(ecc_key->curve == NULL || ecc_key->curve->size != coord_size) {
                    noxtls_ecc_key_free(ecc_key);
                    free(ecc_key);
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }
                rc = noxtls_ecdsa_signature_init(&ecdsa_sig, coord_size);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_ecc_key_free(ecc_key);
                    free(ecc_key);
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }
                rc = noxtls_ecdsa_signature_parse_der(msg + 8, (uint32_t)sig_len, &ecdsa_sig, coord_size);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_ecdsa_signature_free(&ecdsa_sig);
                    noxtls_ecc_key_free(ecc_key);
                    free(ecc_key);
                    free(msg);
                    return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
                }
                rc = noxtls_ecdsa_verify(ecc_key, to_verify, to_verify_len, &ecdsa_sig, verify_hash);
                noxtls_ecdsa_signature_free(&ecdsa_sig);
                noxtls_ecc_key_free(ecc_key);
                free(ecc_key);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    free(msg);
                    return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
                }
            } else if(sig_scheme == TLS_SIGSCHEME_ED25519) {
                if(!cert->has_ed25519 || sig_len != 64) {
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }
                rc = noxtls_ed25519_verify(cert->ed25519_public_key, to_verify, to_verify_len, msg + 8);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    free(msg);
                    return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
                }
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
            } else if(sig_scheme == TLS_SIGSCHEME_ED448) {
                if(!cert->has_ed448 || sig_len != 114) {
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }
                rc = noxtls_ed448_verify(cert->ed448_public_key, to_verify, to_verify_len, msg + 8);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    free(msg);
                    return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
                }
#endif
            } else if(cert->has_mldsa &&
                      (sig_scheme == TLS_SIGSCHEME_MLDSA44 || sig_scheme == TLS_SIGSCHEME_MLDSA65 || sig_scheme == TLS_SIGSCHEME_MLDSA87)) {
#if NOXTLS_FEATURE_ML_DSA
                noxtls_mldsa_param_t mldsa_param = (sig_scheme == TLS_SIGSCHEME_MLDSA44) ? NOXTLS_MLDSA_44 :
                                                   (sig_scheme == TLS_SIGSCHEME_MLDSA65) ? NOXTLS_MLDSA_65 :
                                                   NOXTLS_MLDSA_87;
                rc = noxtls_mldsa_verify(mldsa_param, cert->mldsa_public_key,
                                         to_verify, to_verify_len, msg + 8, sig_len);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    free(msg);
                    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                                    NOXTLS_EVT_VERIFY_SIG_FAIL, 5U, rc);
                    return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
                }
#else
                free(msg);
                return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
            } else if(cert->has_slhdsa &&
                      sig_scheme >= TLS_SIGSCHEME_SLHDSA_SHA2_128S &&
                      sig_scheme <= TLS_SIGSCHEME_SLHDSA_SHAKE_256F) {
#if NOXTLS_FEATURE_SLH_DSA
                noxtls_slhdsa_param_t slhdsa_param = NOXTLS_SLHDSA_NONE;

                rc = tls13_slhdsa_sig_scheme_to_param(sig_scheme, &slhdsa_param);
                if(rc != NOXTLS_RETURN_SUCCESS || cert->slhdsa_param != slhdsa_param) {
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }
                rc = noxtls_slhdsa_verify(slhdsa_param,
                                          cert->slhdsa_public_key,
                                          to_verify,
                                          to_verify_len,
                                          msg + 8,
                                          sig_len);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    free(msg);
                    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                                    NOXTLS_EVT_VERIFY_SIG_FAIL, 6U, rc);
                    return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
                }
#else
                free(msg);
                return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
            } else {
                free(msg);
                NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                                NOXTLS_EVT_VERIFY_SIG_FAIL, 4U, sig_scheme);
                return NOXTLS_RETURN_FAILED;
            }
        }
        /* Client: verify server cert is valid for the requested hostname (SAN or CN) */
        if(ctx->server_name != NULL && ctx->server_name_len > 0) {
            rc = noxtls_x509_certificate_matches_hostname((x509_certificate_t*)ctx->server_cert_parsed,
                (const char*)ctx->server_name, ctx->server_name_len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                free(msg);
                NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                                NOXTLS_EVT_CERT_VERIFY_FAIL, rc, 2U);
                return NOXTLS_RETURN_FAILED;
            }
        }
    }

    /* Append to transcript after verification */
    tls13_append_handshake_message(ctx, msg, msg_len);

    free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Client: receive server Finished and verify verify_data against the transcript.
 * @param[in,out] ctx Client context; derives application traffic secrets after verify.
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
        return NOXTLS_RETURN_BAD_DATA;
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
    rc = noxtls_hmac_compute(hash_algo, finished_key, hash_len, transcript_hash, transcript_len,
                      verify_data, &verify_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(msg);
        return rc;
    }

    if(msg_len != 4U + verify_len) {
        free(msg);
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(noxtls_secret_memcmp(msg + 4, verify_data, verify_len) != 0) {
        free(msg);
        return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
    }

    /* RFC 5929: store first Finished verify_data for tls-unique channel binding (TLS 1.3: server sends first) */
    if(ctx->channel_binding_first_finished_len == 0 && verify_len <= sizeof(ctx->channel_binding_first_finished)) {
        memcpy(ctx->channel_binding_first_finished, msg + 4, verify_len);
        ctx->channel_binding_first_finished_len = verify_len;
    }

    /* Append server Finished to transcript */
    tls13_append_handshake_message(ctx, msg, msg_len);
    ctx->app_secret_transcript_len = ctx->handshake_messages_len;

    free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Client: send an empty Certificate message when authentication was requested but no cert is configured.
 * @param[in,out] ctx Client context with `client_auth_requested` set.
 * @return `NOXTLS_RETURN_SUCCESS` on success; send or encoding error otherwise.
 */
static noxtls_return_t tls13_send_client_certificate_empty(tls13_context_t *ctx)
{
    uint8_t certificate[64];
    uint32_t offset = 0;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_CLIENT) {
        return NOXTLS_RETURN_FAILED;
    }
    certificate[offset++] = TLS_HANDSHAKE_CERTIFICATE;
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;
    certificate[offset++] = ctx->cert_request_context_len;
    if(ctx->cert_request_context_len > 0) {
        if(offset + ctx->cert_request_context_len > sizeof(certificate)) {
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(certificate + offset, ctx->cert_request_context, ctx->cert_request_context_len);
        offset += ctx->cert_request_context_len;
    }
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;
    uint32_t handshake_len = offset - 4;
    certificate[1] = (handshake_len >> 16) & 0xFF;
    certificate[2] = (handshake_len >> 8) & 0xFF;
    certificate[3] = handshake_len & 0xFF;
    {
        noxtls_return_t rc = tls13_send_encrypted_handshake(ctx, certificate, offset);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    tls13_append_handshake_message(ctx, certificate, offset);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Client: send Certificate with the configured client identity (mutual TLS).
 * @param[in,out] ctx Client context with client certificate configured.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_FAILED` if no cert when required.
 */
noxtls_return_t noxtls_tls13_send_client_certificate(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_CLIENT || ctx->client_cert == NULL || ctx->client_cert_len == 0) {
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

    certificate[offset++] = TLS_HANDSHAKE_CERTIFICATE;
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;
    certificate[offset++] = ctx->cert_request_context_len;
    if(ctx->cert_request_context_len > 0) {
        memcpy(certificate + offset, ctx->cert_request_context, ctx->cert_request_context_len);
        offset += ctx->cert_request_context_len;
    }
    uint32_t cert_list_len = ctx->client_cert_len + 5U;
    certificate[offset++] = (cert_list_len >> 16) & 0xFF;
    certificate[offset++] = (cert_list_len >> 8) & 0xFF;
    certificate[offset++] = cert_list_len & 0xFF;
    certificate[offset++] = (ctx->client_cert_len >> 16) & 0xFF;
    certificate[offset++] = (ctx->client_cert_len >> 8) & 0xFF;
    certificate[offset++] = ctx->client_cert_len & 0xFF;
    if(offset + ctx->client_cert_len > TLS_HANDSHAKE_WORKSPACE_SIZE) {
        tls13_release_handshake_cert_buffer(ctx, certificate);
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(certificate + offset, ctx->client_cert, ctx->client_cert_len);
    offset += ctx->client_cert_len;
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;

    uint32_t handshake_len = offset - 4;
    certificate[1] = (handshake_len >> 16) & 0xFF;
    certificate[2] = (handshake_len >> 8) & 0xFF;
    certificate[3] = handshake_len & 0xFF;

    noxtls_return_t rc = tls13_send_encrypted_handshake(ctx, certificate, offset);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        tls13_release_handshake_cert_buffer(ctx, certificate);
        return rc;
    }
    tls13_append_handshake_message(ctx, certificate, offset);
    tls13_release_handshake_cert_buffer(ctx, certificate);
    return NOXTLS_RETURN_SUCCESS;
}

/** @brief Encode ECDSA signature (r, s) to DER for TLS CertificateVerify. Returns bytes written or 0 on error. 
 *
 * @param[in] sig The ECDSA signature to encode
 * @param[out] der The output DER encoded signature
 * @param[in] der_max The maximum length of the output DER encoded signature
 * @return The number of bytes written, or 0 if the signature is invalid or the output DER encoded signature is too long
 */
static uint32_t tls13_ecdsa_signature_to_der(const ecdsa_signature_t *sig, uint8_t *der, uint32_t der_max)
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
 * @brief Client: sign the handshake transcript and send CertificateVerify.
 *
 * Supports RSA-PSS, ECDSA P-256/P-384, Ed25519, Ed448, and ML-DSA schemes per configured client key.
 *
 * @param[in,out] ctx Client context with client private key configured.
 * @return `NOXTLS_RETURN_SUCCESS` on success; signing or send error otherwise.
 */
noxtls_return_t noxtls_tls13_send_client_certificate_verify(tls13_context_t *ctx)
{
    tls13_cv_msg_buf_t cv_msg;
    uint32_t offset = 0;
    static const char ctx_str[] = "TLS 1.3, client CertificateVerify";
    uint8_t to_sign[64 + sizeof(ctx_str) + 1 + 64];
    uint32_t to_sign_len;
    noxtls_return_t rc;
    uint16_t sig_scheme = 0;
    uint32_t signature_len = 0;

    memset(&cv_msg, 0, sizeof(cv_msg));

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_CLIENT) {
        return NOXTLS_RETURN_FAILED;
    }
    if(ctx->client_private_rsa == NULL && ctx->client_private_ecdsa == NULL && !ctx->client_cert_use_ed25519
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
        && !ctx->client_cert_use_ed448
#endif
        && !ctx->client_cert_use_mldsa &&
        !ctx->client_cert_use_slhdsa
        ) {
        return NOXTLS_RETURN_FAILED;
    }

    if(ctx->client_private_rsa != NULL) {
        sig_scheme = TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256;
    } else if(ctx->client_private_ecdsa != NULL) {
        ecc_key_t *eckey = (ecc_key_t *)ctx->client_private_ecdsa;
        uint32_t coord_size = eckey->curve != NULL ? eckey->curve->size : 32U;
        if(coord_size == 32U) {
            sig_scheme = TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256;
        } else if(coord_size == 48U) {
            sig_scheme = TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384;
        } else {
            return NOXTLS_RETURN_INVALID_ALGORITHM;
        }
    } else if(ctx->client_cert_use_ed25519) {
        sig_scheme = TLS_SIGSCHEME_ED25519;
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
    } else if(ctx->client_cert_use_ed448) {
        sig_scheme = TLS_SIGSCHEME_ED448;
#endif
    } else if(ctx->client_cert_use_mldsa) {
#if NOXTLS_FEATURE_ML_DSA
        sig_scheme = (ctx->client_private_mldsa_param == NOXTLS_MLDSA_44) ? TLS_SIGSCHEME_MLDSA44 :
                     (ctx->client_private_mldsa_param == NOXTLS_MLDSA_65) ? TLS_SIGSCHEME_MLDSA65 :
                     TLS_SIGSCHEME_MLDSA87;
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else if(ctx->client_cert_use_slhdsa) {
#if NOXTLS_FEATURE_SLH_DSA
        sig_scheme = tls13_slhdsa_param_to_sig_scheme(ctx->client_private_slhdsa_param);
        if(sig_scheme == 0U) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else {
        return NOXTLS_RETURN_FAILED;
    }

    rc = tls13_cv_msg_buf_init(&cv_msg, sig_scheme);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_build_certificate_verify_tosign(ctx, sig_scheme, ctx_str,
                                             (uint32_t)(sizeof(ctx_str) - 1U),
                                             to_sign, &to_sign_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        tls13_cv_msg_buf_free(&cv_msg);
        return rc;
    }

    cv_msg.buf[offset++] = TLS_HANDSHAKE_CERTIFICATE_VERIFY;
    cv_msg.buf[offset++] = 0x00;
    cv_msg.buf[offset++] = 0x00;
    cv_msg.buf[offset++] = 0x00;

    if(ctx->client_private_rsa != NULL) {
        signature_len = cv_msg.cap - 8U;
        rc = noxtls_rsa_sign_pss((const rsa_key_t *)ctx->client_private_rsa, to_sign, to_sign_len,
                                 cv_msg.buf + 8, &signature_len, NOXTLS_HASH_SHA_256);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cv_exit;
        }
    } else if(ctx->client_private_ecdsa != NULL) {
        ecc_key_t *eckey = (ecc_key_t *)ctx->client_private_ecdsa;
        uint32_t coord_size = eckey->curve != NULL ? eckey->curve->size : 32;
        noxtls_hash_algos_t sig_hash;
        if(!tls13_ecdsa_sig_scheme_to_hash(sig_scheme, &sig_hash)) {
            rc = NOXTLS_RETURN_INVALID_ALGORITHM;
            goto cv_exit;
        }
        {
            ecdsa_signature_t sig;
            uint32_t der_len;
            rc = noxtls_ecdsa_signature_init(&sig, coord_size);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                goto cv_exit;
            }
            rc = noxtls_ecdsa_sign(eckey, to_sign, to_sign_len, &sig, sig_hash);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_ecdsa_signature_free(&sig);
                goto cv_exit;
            }
            der_len = tls13_ecdsa_signature_to_der(&sig, cv_msg.buf + 8, cv_msg.cap - 8U);
            noxtls_ecdsa_signature_free(&sig);
            if(der_len == 0) {
                rc = NOXTLS_RETURN_FAILED;
                goto cv_exit;
            }
            signature_len = der_len;
        }
    } else if(ctx->client_cert_use_ed25519) {
        rc = noxtls_ed25519_sign(ctx->client_private_ed25519, to_sign, to_sign_len, cv_msg.buf + 8);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cv_exit;
        }
        signature_len = 64;
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
    } else if(ctx->client_cert_use_ed448) {
        rc = noxtls_ed448_sign(ctx->client_private_ed448, to_sign, to_sign_len, cv_msg.buf + 8);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cv_exit;
        }
        signature_len = 114;
#endif
    } else if(ctx->client_cert_use_mldsa) {
#if NOXTLS_FEATURE_ML_DSA
        signature_len = cv_msg.cap - 8U;
        rc = noxtls_mldsa_sign(ctx->client_private_mldsa_param, ctx->client_private_mldsa,
                               to_sign, to_sign_len, cv_msg.buf + 8, &signature_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cv_exit;
        }
#else
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
        goto cv_exit;
#endif
    } else if(ctx->client_cert_use_slhdsa) {
#if NOXTLS_FEATURE_SLH_DSA
        signature_len = cv_msg.cap - 8U;
        rc = noxtls_slhdsa_sign(ctx->client_private_slhdsa_param,
                                ctx->client_private_slhdsa,
                                to_sign,
                                to_sign_len,
                                cv_msg.buf + 8,
                                &signature_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cv_exit;
        }
#else
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
        goto cv_exit;
#endif
    } else {
        rc = NOXTLS_RETURN_FAILED;
        goto cv_exit;
    }

    cv_msg.buf[4] = (uint8_t)(sig_scheme >> 8);
    cv_msg.buf[5] = (uint8_t)sig_scheme;
    cv_msg.buf[6] = (uint8_t)(signature_len >> 8);
    cv_msg.buf[7] = (uint8_t)signature_len;
    offset = 8U + signature_len;
    {
        uint32_t handshake_len = offset - 4U;
        cv_msg.buf[1] = (uint8_t)((handshake_len >> 16) & 0xFF);
        cv_msg.buf[2] = (uint8_t)((handshake_len >> 8) & 0xFF);
        cv_msg.buf[3] = (uint8_t)(handshake_len & 0xFF);
    }

    rc = tls13_send_encrypted_handshake(ctx, cv_msg.buf, offset);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cv_exit;
    }
    tls13_append_handshake_message(ctx, cv_msg.buf, offset);
    rc = NOXTLS_RETURN_SUCCESS;

cv_exit:
    tls13_cv_msg_buf_free(&cv_msg);
    return rc;
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
    rc = noxtls_hmac_compute(hash_algo, finished_key, hash_len, transcript_hash, transcript_len,
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
 * @brief Get TLS channel binding data (RFC 5929). Call after handshake completes.
 * @param[in] ctx            Established TLS 1.3 context.
 * @param[in] binding_type   `NOXTLS_TLS_CHANNEL_BINDING_TLS_UNIQUE` or `NOXTLS_TLS_CHANNEL_BINDING_TLS_SERVER_END_POINT`.
 * @param[out] out           Output buffer for binding data.
 * @param[in,out] out_len    On input, size of @p out; on success, bytes written (32/48/64 depending on type).
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers;
 *         `NOXTLS_RETURN_FAILED` if binding is unavailable or type is invalid.
 */
noxtls_return_t noxtls_tls13_get_channel_binding(tls13_context_t *ctx, uint32_t binding_type, uint8_t *out, uint32_t *out_len)
{
    if(ctx == NULL || out == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(binding_type == NOXTLS_TLS_CHANNEL_BINDING_TLS_UNIQUE) {
        if(ctx->channel_binding_first_finished_len == 0) {
            return NOXTLS_RETURN_FAILED;
        }
        if(*out_len < ctx->channel_binding_first_finished_len) {
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(out, ctx->channel_binding_first_finished, ctx->channel_binding_first_finished_len);
        *out_len = ctx->channel_binding_first_finished_len;
        return NOXTLS_RETURN_SUCCESS;
    }

    if(binding_type == NOXTLS_TLS_CHANNEL_BINDING_TLS_SERVER_END_POINT) {
        if(ctx->server_cert == NULL || ctx->server_cert_len == 0 || ctx->server_cert_parsed == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_hash_algos_t hash_algo;
        if(noxtls_x509_get_channel_binding_hash_algo((const x509_certificate_t*)ctx->server_cert_parsed, &hash_algo) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        uint32_t hash_size = (hash_algo == NOXTLS_HASH_SHA_384 || hash_algo == NOXTLS_HASH_SHA_512) ? 48U : 32U;
        if(hash_algo == NOXTLS_HASH_SHA_512) {
            hash_size = 64U;
        }
        if(*out_len < hash_size) {
            return NOXTLS_RETURN_FAILED;
        }
        if(hash_algo == NOXTLS_HASH_SHA_256 || hash_algo == NOXTLS_HASH_SHA_224) {
            noxtls_sha_ctx_t sha_ctx;
            if(noxtls_sha256_init(&sha_ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_FAILED;
            }
            noxtls_sha256_update(&sha_ctx, (uint8_t *)ctx->server_cert, ctx->server_cert_len);
            if(noxtls_sha256_finish(&sha_ctx, out) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_FAILED;
            }
            *out_len = 32U;
            return NOXTLS_RETURN_SUCCESS;
        }
        if(hash_algo == NOXTLS_HASH_SHA_384 || hash_algo == NOXTLS_HASH_SHA_512) {
            noxtls_sha512_ctx_t sha_ctx;
            if(noxtls_sha512_init(&sha_ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_FAILED;
            }
            noxtls_sha512_update(&sha_ctx, ctx->server_cert, ctx->server_cert_len);
            if(noxtls_sha512_finish(&sha_ctx, out) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_FAILED;
            }
            *out_len = (hash_algo == NOXTLS_HASH_SHA_384) ? 48U : 64U;
            return NOXTLS_RETURN_SUCCESS;
        }
        return NOXTLS_RETURN_FAILED;
    }

    return NOXTLS_RETURN_FAILED;
}

/**
 * @brief Client: run the full TLS 1.3 handshake through application key installation.
 * @param[in,out] ctx Initialized client context.
 * @return `NOXTLS_RETURN_SUCCESS` when application keys are ready; error from any handshake step.
 */
noxtls_return_t noxtls_tls13_connect(tls13_context_t *ctx)
{
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_CLIENT) {
        return NOXTLS_RETURN_FAILED;
    }

    if(ctx->client_handshake_step == TLS13_CLIENT_HS_STEP_NONE || ctx->base.base.state != TLS_STATE_HANDSHAKING) {
        s_tls13_last_connect_fail_step[0] = '\0';
        ctx->base.base.state = TLS_STATE_HANDSHAKING;
        ctx->peer_compat_ccs_seen = 0U;
        ctx->received_hrr = 0U;
        ctx->client_handshake_step = TLS13_CLIENT_HS_STEP_SEND_CH;
        NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_START);
    }

    while(1) {
        switch((tls13_client_handshake_step_t)ctx->client_handshake_step) {
            case TLS13_CLIENT_HS_STEP_SEND_CH:
                noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: send_client_hello...\n");
                NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_SEND_CH);
                rc = noxtls_tls13_send_client_hello(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_send_client_hello rc=%d\n", rc);
                    tls13_connect_log_fail(ctx, "send_client_hello", rc);
                    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_CH, rc);
                    return rc;
                }
                NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_CH, rc);
                if(ctx->ticket_stored && ctx->resumption_psk_len > 0) {
                    rc = tls13_derive_early_data_keys(ctx);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        noxtls_debug_printf("[TLS13_DEBUG] tls13_derive_early_data_keys rc=%d\n", rc);
                        ctx->early_data_phase = 0;
                    }
                }
                ctx->client_handshake_step = TLS13_CLIENT_HS_STEP_RECV_SH;
                break;

            case TLS13_CLIENT_HS_STEP_RECV_SH:
                noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: recv_server_hello...\n");
                NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_RECV_SH);
                rc = noxtls_tls13_recv_server_hello(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_recv_server_hello rc=%d\n", rc);
                    tls13_connect_log_fail(ctx, "recv_server_hello", rc);
                    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_SH, rc);
                    return rc;
                }
                NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_SH, rc);
                ctx->client_handshake_step = TLS13_CLIENT_HS_STEP_RECV_ENC_EXT;
                break;

            case TLS13_CLIENT_HS_STEP_RECV_ENC_EXT:
                noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: recv_encrypted_extensions...\n");
                rc = noxtls_tls13_recv_encrypted_extensions(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_recv_encrypted_extensions rc=%d\n", rc);
                    tls13_connect_log_fail(ctx, "recv_encrypted_extensions", rc);
                    return rc;
                }
                ctx->client_handshake_step = TLS13_CLIENT_HS_STEP_RECV_CERT_REQ;
                break;

            case TLS13_CLIENT_HS_STEP_RECV_CERT_REQ:
                noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: recv_certificate_request...\n");
                rc = noxtls_tls13_recv_certificate_request(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_recv_certificate_request rc=%d\n", rc);
                    tls13_connect_log_fail(ctx, "recv_certificate_request", rc);
                    return rc;
                }
                ctx->client_handshake_step =
                    ctx->psk_in_use ? TLS13_CLIENT_HS_STEP_RECV_FINISHED : TLS13_CLIENT_HS_STEP_RECV_CERT;
                break;

            case TLS13_CLIENT_HS_STEP_RECV_CERT:
                noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: recv_certificate...\n");
                NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_VERIFY_CERT);
                rc = noxtls_tls13_recv_certificate(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_recv_certificate rc=%d\n", rc);
                    tls13_connect_log_fail(ctx, "recv_certificate", rc);
                    if(ctx->base.base.state != TLS_STATE_CLOSED) {
                        if(tls13_is_certificate_validation_error(rc)) {
                            tls13_send_fatal_alert(ctx, TLS_ALERT_BAD_CERTIFICATE);
                        } else {
                            tls13_send_handshake_alert_for_error(ctx, rc);
                        }
                        ctx->base.base.state = TLS_STATE_CLOSED;
                    }
                    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_VERIFY_CERT, rc);
                    return rc;
                }
                NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_VERIFY_CERT, rc);
                ctx->client_handshake_step = TLS13_CLIENT_HS_STEP_RECV_CERT_VERIFY;
                break;

            case TLS13_CLIENT_HS_STEP_RECV_CERT_VERIFY:
                noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: recv_certificate_verify...\n");
                NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_RECV_CERT_VERIFY);
                rc = noxtls_tls13_recv_certificate_verify(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_recv_certificate_verify rc=%d\n", rc);
                    tls13_connect_log_fail(ctx, "recv_certificate_verify", rc);
                    if(ctx->base.base.state != TLS_STATE_CLOSED) {
                        tls13_send_handshake_alert_for_error(ctx, rc);
                        ctx->base.base.state = TLS_STATE_CLOSED;
                    }
                    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_CERT_VERIFY, rc);
                    return rc;
                }
                NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_CERT_VERIFY, rc);
                ctx->client_handshake_step = TLS13_CLIENT_HS_STEP_RECV_FINISHED;
                break;

            case TLS13_CLIENT_HS_STEP_RECV_FINISHED:
                noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: recv_finished...\n");
                NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_RECV_FINISHED);
                rc = noxtls_tls13_recv_finished(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_recv_finished rc=%d\n", rc);
                    tls13_connect_log_fail(ctx, "recv_finished", rc);
                    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_FINISHED, rc);
                    return rc;
                }
                NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_FINISHED, rc);
                ctx->client_handshake_step = TLS13_CLIENT_HS_STEP_DERIVE_APP_SECRETS;
                break;

            case TLS13_CLIENT_HS_STEP_DERIVE_APP_SECRETS:
                noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: derive_application_secrets...\n");
                rc = tls13_derive_application_secrets(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_debug_printf("[TLS13_DEBUG] tls13_derive_application_secrets rc=%d\n", rc);
                    tls13_connect_log_fail(ctx, "derive_application_secrets", rc);
                    return rc;
                }
                ctx->client_handshake_step = TLS13_CLIENT_HS_STEP_SEND_CLIENT_AUTH;
                break;

            case TLS13_CLIENT_HS_STEP_SEND_CLIENT_AUTH:
                if(ctx->client_auth_requested) {
                    if(ctx->client_cert != NULL && ctx->client_cert_len > 0 &&
                       (ctx->client_private_rsa != NULL || ctx->client_private_ecdsa != NULL || ctx->client_cert_use_ed25519
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
                        || ctx->client_cert_use_ed448
#endif
                        )) {
                        noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: send_client_certificate...\n");
                        rc = noxtls_tls13_send_client_certificate(ctx);
                        if(rc != NOXTLS_RETURN_SUCCESS) {
                            noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_send_client_certificate rc=%d\n", rc);
                            tls13_connect_log_fail(ctx, "send_client_certificate", rc);
                            return rc;
                        }
                        noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: send_client_certificate_verify...\n");
                        rc = noxtls_tls13_send_client_certificate_verify(ctx);
                        if(rc != NOXTLS_RETURN_SUCCESS) {
                            noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_send_client_certificate_verify rc=%d\n", rc);
                            tls13_connect_log_fail(ctx, "send_client_certificate_verify", rc);
                            return rc;
                        }
                    } else {
                        noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: send_client_certificate (empty)...\n");
                        rc = tls13_send_client_certificate_empty(ctx);
                        if(rc != NOXTLS_RETURN_SUCCESS) {
                            noxtls_debug_printf("[TLS13_DEBUG] tls13_send_client_certificate_empty rc=%d\n", rc);
                            tls13_connect_log_fail(ctx, "send_client_certificate_empty", rc);
                            return rc;
                        }
                    }
                }
                ctx->client_handshake_step = TLS13_CLIENT_HS_STEP_SEND_EOED;
                break;

            case TLS13_CLIENT_HS_STEP_SEND_EOED:
                if(ctx->early_data_accepted && !ctx->sent_end_of_early_data) {
                    uint8_t eoed[4];

                    eoed[0] = TLS_HANDSHAKE_END_OF_EARLY_DATA;
                    eoed[1] = 0;
                    eoed[2] = 0;
                    eoed[3] = 0;
                    rc = tls13_append_handshake_message(ctx, eoed, 4);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        tls13_connect_log_fail(ctx, "append_end_of_early_data", rc);
                        return rc;
                    }
                    noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: send EndOfEarlyData...\n");
                    rc = tls13_send_encrypted_handshake(ctx, eoed, 4);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_send EndOfEarlyData rc=%d\n", rc);
                        tls13_connect_log_fail(ctx, "send_end_of_early_data", rc);
                        return rc;
                    }
                    ctx->sent_end_of_early_data = 1;
                }
                ctx->client_handshake_step = TLS13_CLIENT_HS_STEP_SEND_FINISHED;
                break;

            case TLS13_CLIENT_HS_STEP_SEND_FINISHED:
                noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: send_finished...\n");
                NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_SEND_FINISHED);
                rc = noxtls_tls13_send_finished(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_send_finished rc=%d\n", rc);
                    tls13_connect_log_fail(ctx, "send_finished", rc);
                    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_FINISHED, rc);
                    return rc;
                }
                NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_FINISHED, rc);
                ctx->client_handshake_step = TLS13_CLIENT_HS_STEP_INSTALL_APP_KEYS;
                break;

            case TLS13_CLIENT_HS_STEP_INSTALL_APP_KEYS:
                noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_connect: install_application_keys...\n");
                rc = tls13_install_application_keys(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_debug_printf("[TLS13_DEBUG] tls13_install_application_keys rc=%d\n", rc);
                    tls13_connect_log_fail(ctx, "install_application_keys", rc);
                    return rc;
                }
                ctx->base.base.state = TLS_STATE_CONNECTED;
                ctx->client_handshake_step = TLS13_CLIENT_HS_STEP_NONE;
                NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_CONNECTED);
#if NOXTLS_FEATURE_DTLS
                noxtls_dtls_mark_validated(&ctx->base);
#endif
                tls13_try_recv_nst(ctx);
                return NOXTLS_RETURN_SUCCESS;

            case TLS13_CLIENT_HS_STEP_NONE:
            default:
                ctx->client_handshake_step = TLS13_CLIENT_HS_STEP_SEND_CH;
                break;
        }
    }
}

/** @brief Process ALPN after ClientHello extension parse; sends fatal alerts on failure. 
 *
 * @param[in] ctx The context to process the ALPN negotiation from
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, 
 *         NOXTLS_RETURN_BAD_DATA if the ALPN is invalid, or NOXTLS_RETURN_NOT_SUPPORTED if the ALPN is not supported
 */
static noxtls_return_t tls13_process_alpn_negotiation(tls13_context_t *ctx)
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
                                                sizeof(ctx->negotiated_alpn) - 1U,
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


/**
 * @brief Free the client hello extension type order
 *
 * @param[in] ctx The context to free the client hello extension type order from
 */
static void tls13_hrr_first_ch_ext_order_free(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return;
    }
    if(ctx->hrr_first_clienthello_ext_order != NULL) {
        free(ctx->hrr_first_clienthello_ext_order);
        ctx->hrr_first_clienthello_ext_order = NULL;
    }
    ctx->hrr_first_clienthello_ext_order_count = 0U;
}

/**
 * @brief Extract the client hello extension type order
 *
 * @param[in] ext_block The extension block to extract the client hello extension type order from
 * @param[in] ext_block_len The length of the extension block
 * @param[out] out_types The output types
 * @param[out] out_count The output count
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the output types or count is NULL, NOXTLS_RETURN_BAD_DATA if the extension block is invalid, or NOXTLS_RETURN_FAILED if the allocation fails
 */
static noxtls_return_t tls13_extract_clienthello_extension_type_order(const uint8_t *ext_block,
                                                                      uint32_t ext_block_len,
                                                                      uint16_t **out_types,
                                                                      uint32_t *out_count)
{
    uint32_t ext_total;
    uint32_t pos;
    uint32_t end;
    uint32_t cap = 64U;
    uint32_t count = 0U;
    uint16_t *types = NULL;

    if(out_types == NULL || out_count == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    *out_types = NULL;
    *out_count = 0U;
    if(ext_block == NULL || ext_block_len < 2U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    ext_total = ((uint32_t)ext_block[0] << 8) | (uint32_t)ext_block[1];
    pos = 2U;
    if(ext_total > ext_block_len - 2U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    end = pos + ext_total;
    if(pos >= end) {
        return NOXTLS_RETURN_SUCCESS;
    }
    types = (uint16_t*)malloc(cap * sizeof(uint16_t));
    if(types == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    while(pos + 4U <= end) {
        uint16_t etype = (uint16_t)(((uint16_t)ext_block[pos] << 8) | (uint16_t)ext_block[pos + 1U]);
        uint16_t elen = (uint16_t)(((uint16_t)ext_block[pos + 2U] << 8) | (uint16_t)ext_block[pos + 3U]);
        pos += 4U;
        if((uint32_t)elen > end - pos) {
            free(types);
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(count >= TLS13_CLIENTHELLO_EXT_ORDER_MAX) {
            free(types);
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(count >= cap) {
            uint32_t ncap = cap * 2U;
            uint16_t *nt;
            if(ncap > TLS13_CLIENTHELLO_EXT_ORDER_MAX) {
                free(types);
                return NOXTLS_RETURN_BAD_DATA;
            }
            nt = (uint16_t*)realloc(types, ncap * sizeof(uint16_t));
            if(nt == NULL) {
                free(types);
                return NOXTLS_RETURN_FAILED;
            }
            types = nt;
            cap = ncap;
        }
        types[count++] = etype;
        pos += (uint32_t)elen;
    }
    if(pos != end) {
        free(types);
        return NOXTLS_RETURN_BAD_DATA;
    }
    *out_types = types;
    *out_count = count;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Capture the first ClientHello extension type order
 *
 * @param[in] ctx The context to capture the first ClientHello extension type order from
 * @param[in] ext_block The extension block to capture the first ClientHello extension type order from
 * @param[in] ext_block_len The length of the extension block to capture the first ClientHello extension type order from
 * @return The return code
 */
static noxtls_return_t tls13_hrr_first_ch_ext_order_capture(tls13_context_t *ctx,
                                                            const uint8_t *ext_block,
                                                            uint32_t ext_block_len)
{
    uint16_t *types = NULL;
    uint32_t count = 0U;
    noxtls_return_t rc = tls13_extract_clienthello_extension_type_order(ext_block, ext_block_len, &types, &count);

    tls13_hrr_first_ch_ext_order_free(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /*
     * RFC 8446 §4.1.2: HRR allows the second ClientHello to omit early_data and
     * add a cookie extension. Those differences are not extension-order violations.
     */
    if(types != NULL && count > 0U) {
        uint32_t w = 0U;
        for(uint32_t r = 0U; r < count; r++) {
            if(types[r] == TLS_EXTENSION_EARLY_DATA || types[r] == TLS_EXTENSION_COOKIE) {
                continue;
            }
            types[w++] = types[r];
        }
        count = w;
    }
    ctx->hrr_first_clienthello_ext_order = types;
    ctx->hrr_first_clienthello_ext_order_count = count;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Server: receive and parse ClientHello (cipher suites, groups, key shares, extensions).
 * @param[in,out] ctx Server context; may send HelloRetryRequest on mismatch.
 * @return `NOXTLS_RETURN_SUCCESS` on success; I/O, parse, or policy error otherwise.
 */
noxtls_return_t noxtls_tls13_recv_client_hello(tls13_context_t *ctx)
{
    tls_record_t record;
    tls_record_t next_record;
    uint32_t offset;
    uint32_t client_hello_total_len = 0;
    uint32_t assembled_len = 0;
    uint16_t version;
    uint8_t session_id_len;
    uint16_t cipher_suites_len;
    uint8_t compression_methods_len;
    int saw_key_share_ext = 0;
    int key_share_empty_or_invalid = 0;
    const uint8_t *psk_binder_transcript_prefix = NULL;
    uint32_t psk_binder_transcript_prefix_len = 0U;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Check if we have a pending Client Hello from version negotiation */
    if(ctx->base.base.pending_client_hello != NULL && ctx->base.base.pending_client_hello_len > 0) {
        record.type = TLS_RECORD_HANDSHAKE;
        record.version = TLS_VERSION_1_3;  /* Legacy version for TLS 1.3 */
        (void)record.version;
        if(ctx->base.base.pending_client_hello_len > TLS_MAX_CLIENT_HELLO_BYTES) {
            return NOXTLS_RETURN_FAILED;
        }
        record.length = (uint32_t)ctx->base.base.pending_client_hello_len;
        record.data = (uint8_t*)malloc((size_t)record.length);
        if(record.length > 0 && record.data == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(record.data, ctx->base.base.pending_client_hello, (size_t)record.length);
        free(ctx->base.base.pending_client_hello);
        ctx->base.base.pending_client_hello = NULL;
        ctx->base.base.pending_client_hello_len = 0;
    } else {
        noxtls_return_t rc;
        for(;;) {
            rc = noxtls_tls_recv_record(&ctx->base.base, &record);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            if(record.length > 0 && record.data == NULL) {
                return NOXTLS_RETURN_FAILED;
            }
            if(record.type == TLS_RECORD_CHANGE_CIPHER_SPEC) {
                noxtls_return_t ccs_rc = tls13_handle_peer_compat_ccs(ctx, &record);
                free(record.data);
                if(ccs_rc != NOXTLS_RETURN_SUCCESS) {
                    return NOXTLS_RETURN_TLS_ERROR;
                }
                continue;
            }
            if(record.type == TLS_RECORD_ACK && tls13_is_dtls(ctx)) {
                if(record.length > 0 && record.data != NULL) {
                    tls13_dtls_handle_ack(ctx, record.data, record.length);
                }
                free(record.data);
                continue;
            }
            /*
             * After HelloRetryRequest, the client may still have bogus 0-RTT ApplicationData
             * in the TCP buffer (sent immediately after the first ClientHello). Skip those
             * records until the second ClientHello handshake record arrives.
             */
            if(ctx->sent_hrr && record.type == TLS_RECORD_APPLICATION_DATA) {
                free(record.data);
                continue;
            }
            break;
        }
    }
    
    if(record.type != TLS_RECORD_HANDSHAKE || record.length < 4) {
        tls13_accept_log_fail_detail(ctx, "recv_client_hello", "record_type", NOXTLS_RETURN_TLS_ERROR);
        free(record.data);
        return NOXTLS_RETURN_TLS_ERROR;
    }

    /* Reassemble fragmented ClientHello that spans multiple handshake records. */
    client_hello_total_len = 4U + (((uint32_t)record.data[1] << 16) |
                                   ((uint32_t)record.data[2] << 8) |
                                   (uint32_t)record.data[3]);
    if(client_hello_total_len > TLS_MAX_CLIENT_HELLO_BYTES || client_hello_total_len < 38U) {
        tls13_accept_log_fail_detail(ctx, "recv_client_hello", "hello_len", NOXTLS_RETURN_TLS_ERROR);
        free(record.data);
        return NOXTLS_RETURN_TLS_ERROR;
    }
    assembled_len = (uint32_t)record.length;
    while(assembled_len < client_hello_total_len) {
        noxtls_return_t rc = noxtls_tls_recv_record(&ctx->base.base, &next_record);
        uint8_t *new_buf;
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(record.data);
            return rc;
        }
        if(next_record.length > 0 && next_record.data == NULL) {
            free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        if(next_record.type != TLS_RECORD_HANDSHAKE) {
            free(next_record.data);
            free(record.data);
            return NOXTLS_RETURN_TLS_ERROR;
        }
        if(next_record.length > UINT32_MAX - assembled_len) {
            free(next_record.data);
            free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        new_buf = (uint8_t*)realloc(record.data, assembled_len + (uint32_t)next_record.length);
        if(new_buf == NULL) {
            free(next_record.data);
            free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        record.data = new_buf;
        if(next_record.length > 0 && next_record.data != NULL) {
            memcpy(record.data + assembled_len, next_record.data, next_record.length);
        }
        assembled_len += (uint32_t)next_record.length;
        free(next_record.data);
    }

    if(assembled_len != client_hello_total_len || assembled_len < 38U) {
        tls13_accept_log_fail_detail(ctx, "recv_client_hello", "reassembly", NOXTLS_RETURN_TLS_ERROR);
        free(record.data);
        return NOXTLS_RETURN_TLS_ERROR;
    }
    record.length = assembled_len;

    
    if(record.data[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        tls13_accept_log_fail_detail(ctx, "recv_client_hello", "handshake_type", NOXTLS_RETURN_TLS_ERROR);
        free(record.data);
        return NOXTLS_RETURN_TLS_ERROR;
    }

    if(ctx->sent_hrr && ctx->handshake_messages != NULL && ctx->handshake_messages_len > 0U) {
        psk_binder_transcript_prefix = ctx->handshake_messages;
        psk_binder_transcript_prefix_len = ctx->handshake_messages_len;
    } else {
        /* First ClientHello participates in the transcript immediately. */
        tls13_append_handshake_message(ctx, record.data, record.length);
    }
    offset = 4;  /* Skip handshake header */
    
    /* Version */
    version = (record.data[offset] << 8) | record.data[offset + 1];
    if((tls13_is_dtls(ctx) && version != DTLS_VERSION_1_2) ||
       (!tls13_is_dtls(ctx) && version != TLS_VERSION_1_2)) {
        (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_PROTOCOL_VERSION);
        /*
         * Prevent duplicate generic alert from accept() path after we've sent
         * the standards-compliant protocol_version alert.
         */
        ctx->peer_alert_received = 1;
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    offset += 2;
    
    /* Client Random (32 bytes) */
    memcpy(ctx->client_random, record.data + offset, TLS_RANDOM_SIZE);
    offset += TLS_RANDOM_SIZE;
    
    /* Session ID length + value (legacy_session_id to echo in ServerHello) */
    if(offset >= record.length) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    session_id_len = record.data[offset++];
    if(session_id_len > TLS_SESSION_ID_MAX_LEN || offset + session_id_len > record.length) {
        if(ctx->base.base.send_callback != NULL) {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
        }
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    ctx->client_legacy_session_id_len = session_id_len;
    if(session_id_len > 0) {
        memcpy(ctx->client_legacy_session_id, record.data + offset, session_id_len);
    }
    noxtls_debug_printf("[TLS13_DEBUG] client_legacy_session_id_len=%u\n", ctx->client_legacy_session_id_len);
    offset += session_id_len;

    if(tls13_is_dtls(ctx)) {
        uint8_t legacy_cookie_len;
        if(offset + 1U > record.length) {
            free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        legacy_cookie_len = record.data[offset++];
        if(offset + legacy_cookie_len > record.length) {
            free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        if(legacy_cookie_len != 0U) {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_ILLEGAL_PARAMETER);
            ctx->peer_alert_received = 1;
            free(record.data);
            return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
        }
        offset += legacy_cookie_len;
    }
    
    /* Cipher suites length */
    cipher_suites_len = (record.data[offset] << 8) | record.data[offset + 1];
    offset += 2;
    
    /* Parse and select first supported cipher suite from client's list */
    {
        static const uint16_t supported[] = {
            TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
            TLS_CIPHER_SUITE_AES_128_CCM_SHA256,
            TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256,
            TLS_CIPHER_SUITE_AES_256_GCM_SHA384,
            TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256
        };
        const uint16_t *supported_suites = supported;
        uint32_t num_supported = sizeof(supported) / sizeof(supported[0]);
        if(ctx->server_cipher_suites != NULL && ctx->server_cipher_suites_count > 0) {
            supported_suites = ctx->server_cipher_suites;
            num_supported = ctx->server_cipher_suites_count;
        }
        ctx->cipher_suite = 0;
        for(uint32_t i = 0; i + 2 <= cipher_suites_len; i += 2) {
            uint16_t candidate = (record.data[offset + i] << 8) | record.data[offset + i + 1];
            for(uint32_t j = 0; j < num_supported; j++) {
                if(candidate == supported_suites[j]) {
                    ctx->cipher_suite = candidate;
                    break;
                }
            }
            if(ctx->cipher_suite != 0) break;
        }
        if(ctx->cipher_suite == 0) {
            tls13_accept_log_fail_detail(ctx, "recv_client_hello", "cipher_suite", NOXTLS_RETURN_FAILED);
            free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
    }
    offset += cipher_suites_len;
    
    /* Legacy compression methods (RFC 8446 ?4.1.2: exactly one octet, set to zero) */
    if(offset >= record.length) {
        free(record.data);
        return NOXTLS_RETURN_BAD_DATA;
    }
    compression_methods_len = record.data[offset++];
    if(offset + compression_methods_len > record.length) {
        free(record.data);
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(compression_methods_len != 1U || record.data[offset] != 0U) {
        free(record.data);
        return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
    }
    offset += compression_methods_len;

    /*
     * RFC 8446 ?4.1.2: the client's second ClientHello must be the same as the first except for
     * listed changes; reordering extensions is not allowed (tlsfuzzer test_tls13_shuffled_extentions).
     */
    if(ctx->sent_hrr && ctx->hrr_first_clienthello_ext_order != NULL) {
        uint32_t ext_remain = (offset < record.length) ? (record.length - offset) : 0U;
        uint16_t *cur_types = NULL;
        uint32_t cur_count = 0U;
        noxtls_return_t ord_rc = tls13_extract_clienthello_extension_type_order(record.data + offset, ext_remain,
                                                                                &cur_types, &cur_count);
        if(ord_rc != NOXTLS_RETURN_SUCCESS) {
            free(record.data);
            tls13_hrr_first_ch_ext_order_free(ctx);
            return ord_rc;
        }
        if(cur_types != NULL && cur_count > 0U) {
            uint32_t w = 0U;
            for(uint32_t r = 0U; r < cur_count; r++) {
                if(cur_types[r] == TLS_EXTENSION_EARLY_DATA || cur_types[r] == TLS_EXTENSION_COOKIE) {
                    continue;
                }
                cur_types[w++] = cur_types[r];
            }
            cur_count = w;
        }
        if(cur_count != ctx->hrr_first_clienthello_ext_order_count ||
           (cur_count > 0U &&
            memcmp(cur_types, ctx->hrr_first_clienthello_ext_order,
                   (size_t)cur_count * sizeof(uint16_t)) != 0)) {
            free(cur_types);
            free(record.data);
            tls13_hrr_first_ch_ext_order_free(ctx);
            return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
        }
        free(cur_types);
        tls13_hrr_first_ch_ext_order_free(ctx);
    }
    
    /* Parse extensions (especially key_share extension) */
    {
        uint32_t ext_scan_offset = offset;
        if(ext_scan_offset + 2U <= record.length) {
            uint32_t ext_total_len = ((uint32_t)record.data[ext_scan_offset] << 8) |
                                     (uint32_t)record.data[ext_scan_offset + 1U];
            uint32_t ext_pos = ext_scan_offset + 2U;
            uint32_t ext_end = ext_pos + ext_total_len;
            if(ext_end <= record.length) {
                while(ext_pos + 4U <= ext_end) {
                    uint16_t ext_type = ((uint16_t)record.data[ext_pos] << 8) |
                                        (uint16_t)record.data[ext_pos + 1U];
                    uint16_t ext_len = ((uint16_t)record.data[ext_pos + 2U] << 8) |
                                       (uint16_t)record.data[ext_pos + 3U];
                    ext_pos += 4U;
                    if(ext_pos + ext_len > ext_end) {
                        break;
                    }
                    if(ext_type == TLS_EXTENSION_KEY_SHARE) {
                        saw_key_share_ext = 1;
                        if(ext_len < 2U) {
                            key_share_empty_or_invalid = 1;
                        } else {
                            uint16_t list_len = ((uint16_t)record.data[ext_pos] << 8) |
                                                (uint16_t)record.data[ext_pos + 1U];
                            if((uint32_t)list_len != (uint32_t)(ext_len - 2U)) {
                                key_share_empty_or_invalid = 1;
                            }
                        }
                    }
                    ext_pos += ext_len;
                }
            }
        }
    }

    if(offset < record.length) {
        uint32_t extensions_len = record.length - offset;
        if(extensions_len >= 2) {
            /* Re-parse extensions from scratch (important for second ClientHello after HRR). */
            noxtls_tls_extensions_free(&ctx->client_extensions);
            memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
            noxtls_return_t ext_rc = noxtls_tls_parse_extensions(record.data + offset, extensions_len, &ctx->client_extensions);
            if(ext_rc != NOXTLS_RETURN_SUCCESS) {
                tls13_accept_log_fail_detail(ctx, "recv_client_hello", "parse_extensions", ext_rc);
                noxtls_tls_extensions_free(&ctx->client_extensions);
                memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
                free(record.data);
                return ext_rc;
            }
            if(ctx->client_extensions.count > 0U && ctx->client_extensions.extensions != NULL) {
                uint32_t psk_ext_index;
                for(psk_ext_index = 0U; psk_ext_index < ctx->client_extensions.count; psk_ext_index++) {
                    if(ctx->client_extensions.extensions[psk_ext_index].type == TLS_EXTENSION_PRE_SHARED_KEY) {
                        if(psk_ext_index + 1U != ctx->client_extensions.count) {
                            tls13_accept_log_fail_detail(ctx, "recv_client_hello", "pre_shared_key_not_last", NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
                            noxtls_tls_extensions_free(&ctx->client_extensions);
                            memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
                            free(record.data);
                            return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
                        }
                        break;
                    }
                }
            }
            {
                noxtls_return_t obs_rc = tls13_reject_obsolete_client_named_groups(ctx);
                if(obs_rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_tls_extensions_free(&ctx->client_extensions);
                    memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
                    free(record.data);
                    return obs_rc;
                }
            }
            if(ctx->client_extensions.key_share != NULL) {
                noxtls_return_t list_rc = tls13_validate_client_key_share_list(ctx);
                if(list_rc != NOXTLS_RETURN_SUCCESS) {
                    tls13_accept_log_fail_detail(ctx, "recv_client_hello", "key_share_list", list_rc);
                    free(record.data);
                    return list_rc;
                }
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
                    for(uint32_t i = 0; i < ctx->client_key_shares_count; i++) {
                        noxtls_return_t share_rc = tls13_validate_client_key_share(&ctx->client_extensions.key_share->entries[i]);
                        if(share_rc != NOXTLS_RETURN_SUCCESS) {
                            free(record.data);
                            return share_rc;
                        }
                    }
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

    ctx->client_offered_early_data = 0;
    {
        tls_extension_t *ext_early = NULL;
        if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_EARLY_DATA, &ext_early) == NOXTLS_RETURN_SUCCESS && ext_early != NULL) {
            ctx->client_offered_early_data = 1;
        }
    }

    /* RFC 8449: client's record_size_limit = max plaintext we may send to client */
    {
        tls_extension_t *ext_rsl = NULL;
        if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_RECORD_SIZE_LIMIT, &ext_rsl) == NOXTLS_RETURN_SUCCESS &&
           ext_rsl != NULL && ext_rsl->data != NULL && ext_rsl->length >= 2) {
            ctx->record_size_limit_send = (uint16_t)((ext_rsl->data[0] << 8) | ext_rsl->data[1]);
        }
    }

    {
        noxtls_return_t alpn_rc = tls13_process_alpn_negotiation(ctx);
        if(alpn_rc != NOXTLS_RETURN_SUCCESS) {
            free(record.data);
            return alpn_rc;
        }
    }

    ctx->psk_in_use = 0;
    ctx->psk_use_ecdhe = 0;
    ctx->psk_selected_identity = 0;
    {
        tls_extension_t *ext_psk = NULL;
        tls_extension_t *ext_modes = NULL;
        int have_psk = (noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_PRE_SHARED_KEY, &ext_psk) == NOXTLS_RETURN_SUCCESS);
        int have_modes = (noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES, &ext_modes) == NOXTLS_RETURN_SUCCESS);
        if(have_psk && have_modes && ext_psk != NULL && ext_psk->data != NULL && ext_modes != NULL && ext_modes->data != NULL) {
            uint16_t identity_index = 0;
            uint8_t identity_buf[256];
            uint16_t id_len;
            uint32_t binder_offset = 0;
            uint16_t binder_loc_len = 0;
            uint16_t selected_identity;
            noxtls_return_t rc_psk;

            for(identity_index = 0; ; identity_index++) {
                id_len = sizeof(identity_buf);
                rc_psk = tls13_psk_find_clienthello_binder(record.data, record.length,
                                                           identity_index,
                                                           &binder_offset, &binder_loc_len, &selected_identity,
                                                           identity_buf, &id_len);
                if(rc_psk != NOXTLS_RETURN_SUCCESS) {
                    break;
                }
                /* Try session ticket (resumption) first: identity is 16-byte ticket_id */
                if(id_len == TLS13_PSK_TICKET_ID_LEN) {
                    const void *entry = tls13_psk_ticket_store_lookup(identity_buf, (uint32_t)id_len);
                    if(entry != NULL) {
                        noxtls_hash_algos_t hash_algo;
                        uint32_t hash_len;
                        uint32_t key_len;
                        uint8_t expected_binder[64];
                        noxtls_return_t rc_binder;
                        uint8_t entry_psk[64];
                        uint8_t entry_psk_len;
                        uint8_t entry_nonce[TLS13_PSK_TICKET_NONCE_MAX];
                        uint8_t entry_nonce_len;

                        if(tls13_get_cipher_params(noxtls_tls13_psk_ticket_store_entry_cipher_suite(entry), &hash_algo, &hash_len, &key_len) != NOXTLS_RETURN_SUCCESS) {
                            continue;
                        }
                        if(binder_loc_len != hash_len) {
                            continue;
                        }
                        if(tls13_psk_ticket_store_entry_psk(entry, entry_psk, (uint8_t)sizeof(entry_psk), &entry_psk_len,
                                                            entry_nonce, (uint8_t)sizeof(entry_nonce), &entry_nonce_len) != NOXTLS_RETURN_SUCCESS) {
                            continue;
                        }
                        rc_binder = tls13_psk_compute_resumption_binder(hash_algo,
                                                                        entry_psk, entry_psk_len,
                                                                        entry_nonce, entry_nonce_len,
                                                                        record.data, record.length,
                                                                        binder_offset, binder_loc_len,
                                                                        expected_binder,
                                                                        psk_binder_transcript_prefix,
                                                                        psk_binder_transcript_prefix_len);
                        if(rc_binder != NOXTLS_RETURN_SUCCESS) {
                            continue;
                        }
                        if(noxtls_secret_memcmp(record.data + binder_offset, expected_binder, binder_loc_len) != 0) {
                            continue;
                        }
                        {
                            const int dhe_with_shares = (ctx->client_key_shares_count > 0 &&
                                                         noxtls_tls13_psk_mode_offered(ext_modes->data, ext_modes->length,
                                                                                       TLS13_PSK_KE_MODE_PSK_DHE_KE));
                            const int psk_ke_offered = noxtls_tls13_psk_mode_offered(ext_modes->data, ext_modes->length,
                                                                                     TLS13_PSK_KE_MODE_PSK_KE);

                            if(dhe_with_shares) {
                                ctx->psk_use_ecdhe = 1;
                            } else if(psk_ke_offered) {
                                ctx->psk_use_ecdhe = 0;
                            } else {
                                continue;
                            }
                        }
                        ctx->cipher_suite = noxtls_tls13_psk_ticket_store_entry_cipher_suite(entry);
                        memcpy(ctx->psk_key, entry_psk, entry_psk_len);
                        ctx->psk_key_len = entry_psk_len;
                        ctx->psk_selected_identity = identity_index;
                        ctx->psk_in_use = 1;
                        break;
                    }
                }
                /* Try external PSK */
                if(ctx->psk_configured && id_len == ctx->psk_identity_len &&
                   memcmp(identity_buf, ctx->psk_identity, id_len) == 0) {
                    noxtls_hash_algos_t hash_algo;
                    uint32_t hash_len;
                    uint32_t key_len;
                    uint8_t expected_binder[64];

                    if(tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len) != NOXTLS_RETURN_SUCCESS) {
                        continue;
                    }
                    if(binder_loc_len != hash_len) {
                        continue;
                    }
                    if(tls13_psk_compute_external_binder(hash_algo,
                                                          ctx->psk_key, ctx->psk_key_len,
                                                          record.data, record.length,
                                                          binder_offset, binder_loc_len,
                                                          expected_binder,
                                                          psk_binder_transcript_prefix,
                                                          psk_binder_transcript_prefix_len,
                                                          NULL) != NOXTLS_RETURN_SUCCESS) {
                        noxtls_debug_printf("[TLS13_DEBUG] recv_client_hello: external PSK binder compute failed id=%u\n",
                                            (unsigned)identity_index);
                        continue;
                    }
                    if(noxtls_secret_memcmp(record.data + binder_offset, expected_binder, binder_loc_len) != 0) {
                        if(psk_binder_transcript_prefix_len > 0U) {
                            uint8_t prefix_hash[64];
                            uint32_t prefix_hash_len = sizeof(prefix_hash);
                            if(tls13_hash_messages(hash_algo,
                                                   psk_binder_transcript_prefix,
                                                   psk_binder_transcript_prefix_len,
                                                   prefix_hash,
                                                   &prefix_hash_len) == NOXTLS_RETURN_SUCCESS) {
                                noxtls_debug_printf("[TLS13_DEBUG] recv_client_hello: external binder prefix_hash=%02X%02X%02X%02X len=%lu\n",
                                                    prefix_hash[0],
                                                    prefix_hash[1],
                                                    prefix_hash[2],
                                                    prefix_hash[3],
                                                    (unsigned long)psk_binder_transcript_prefix_len);
                            }
                        }
                        noxtls_debug_printf("[TLS13_DEBUG] recv_client_hello: external PSK binder mismatch id=%u len=%u actual=%02X%02X%02X%02X expected=%02X%02X%02X%02X prefix_len=%lu\n",
                                            (unsigned)identity_index,
                                            (unsigned)binder_loc_len,
                                            record.data[binder_offset + 0U],
                                            record.data[binder_offset + 1U],
                                            record.data[binder_offset + 2U],
                                            record.data[binder_offset + 3U],
                                            expected_binder[0],
                                            expected_binder[1],
                                            expected_binder[2],
                                            expected_binder[3],
                                            (unsigned long)psk_binder_transcript_prefix_len);
                        continue;
                    }
                    {
                        const int dhe_with_shares = (ctx->client_key_shares_count > 0 &&
                                                     noxtls_tls13_psk_mode_offered(ext_modes->data, ext_modes->length,
                                                                                   TLS13_PSK_KE_MODE_PSK_DHE_KE));
                        const int psk_ke_offered = noxtls_tls13_psk_mode_offered(ext_modes->data, ext_modes->length,
                                                                                 TLS13_PSK_KE_MODE_PSK_KE);
                        const int preferred_dhe_ok = (ctx->psk_preferred_mode == TLS13_PSK_KE_MODE_PSK_DHE_KE && dhe_with_shares);

                        if(preferred_dhe_ok || (!psk_ke_offered && dhe_with_shares)) {
                            ctx->psk_use_ecdhe = 1;
                        } else if(psk_ke_offered) {
                            ctx->psk_use_ecdhe = 0;
                        } else {
                            continue;
                        }
                    }
                    ctx->psk_in_use = 1;
                    ctx->psk_selected_identity = identity_index;
                    noxtls_debug_printf("[TLS13_DEBUG] recv_client_hello: external PSK accepted id=%u dhe=%u\n",
                                        (unsigned)identity_index,
                                        (unsigned)ctx->psk_use_ecdhe);
                    break;
                }
            }
        }
    }

    /*
     * RFC 8446 ?4.2.8: key_share is required in ClientHello for non-PSK-KE.
     * - Missing key_share -> missing_extension
     * - Present but empty key_share list -> decode_error
     */
    if(key_share_empty_or_invalid) {
        free(record.data);
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(saw_key_share_ext && ctx->client_extensions.supported_groups == NULL) {
        tls13_accept_log_fail_detail(ctx, "recv_client_hello", "missing_supported_groups", NOXTLS_RETURN_NOT_INITIALIZED);
        free(record.data);
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    if((!ctx->psk_in_use || ctx->psk_use_ecdhe) && !saw_key_share_ext) {
        tls13_accept_log_fail_detail(ctx, "recv_client_hello", "missing_key_share", NOXTLS_RETURN_NOT_INITIALIZED);
        free(record.data);
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    /*
     * RFC 8446 ?4.1.4: if the client did not provide a compatible key_share entry
     * (including bogus/unknown groups only), send HelloRetryRequest for the first
     * mutually supported group from supported_groups. Empty key_share list remains
     * a decode_error via key_share_empty_or_invalid above.
     */
    if(!tls13_is_dtls(ctx) &&
       (!ctx->psk_in_use || ctx->psk_use_ecdhe) &&
       tls13_select_server_group(ctx) == 0) {
        noxtls_hash_algos_t hash_algo;
        uint32_t hash_len;
        uint32_t key_len;
        uint16_t selected_group = tls13_select_hrr_group(ctx);
        uint8_t hrr_msg[256];
        uint32_t hrr_len = sizeof(hrr_msg);
        if(selected_group == 0) {
            free(record.data);
            return NOXTLS_RETURN_NOT_SUPPORTED;
        }
        if(tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len) != NOXTLS_RETURN_SUCCESS) {
            tls13_accept_log_fail_detail(ctx, "recv_client_hello", "get_cipher_params", NOXTLS_RETURN_FAILED);
            free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        {
            uint32_t ext_remain = (offset < record.length) ? (record.length - offset) : 0U;
            noxtls_return_t cap_rc = tls13_hrr_first_ch_ext_order_capture(ctx, record.data + offset, ext_remain);
            if(cap_rc != NOXTLS_RETURN_SUCCESS) {
                free(record.data);
                return cap_rc;
            }
        }
        if(tls13_reset_transcript_for_hrr(ctx, hash_algo, hash_len) != NOXTLS_RETURN_SUCCESS) {
            free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        if(tls13_send_hello_retry_request_dtls(ctx, NULL, 0, selected_group, hrr_msg, &hrr_len) != NOXTLS_RETURN_SUCCESS) {
            free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        if(tls13_send_middlebox_compat_ccs(ctx) != NOXTLS_RETURN_SUCCESS) {
            free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        tls13_append_handshake_message(ctx, hrr_msg, hrr_len);
        ctx->awaiting_hrr_client_hello = 1;
        ctx->sent_hrr = 1;
        free(record.data);
        return NOXTLS_RETURN_TIMEOUT;
    }

#if NOXTLS_FEATURE_DTLS
    if(tls13_is_dtls(ctx)) {
        tls_extension_t *ext = NULL;
        int cookie_valid = 0;
        uint8_t hrr_msg[256];
        uint32_t hrr_len = sizeof(hrr_msg);
        uint8_t cookie[32];
        uint32_t cookie_len = sizeof(cookie);
        noxtls_hash_algos_t hash_algo;
        uint32_t hash_len;
        uint32_t key_len;
        uint16_t selected_group = tls13_select_hrr_group(ctx);
        int has_key_share = 0;
        int need_key_share = 1;

        if(ctx->psk_in_use && !ctx->psk_use_ecdhe) {
            need_key_share = 0;
        }
        has_key_share = tls13_client_has_key_share(ctx, selected_group);

        if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_COOKIE, &ext) == NOXTLS_RETURN_SUCCESS) {
            if(ext != NULL && ext->length >= 2U) {
                uint16_t ext_cookie_len = (uint16_t)(((uint16_t)ext->data[0] << 8) | ext->data[1]);
                if(ext_cookie_len <= sizeof(ctx->base.cookie) && ext_cookie_len == ext->length - 2U &&
                   noxtls_dtls_verify_cookie(&ctx->base, ext->data + 2, ext_cookie_len) == NOXTLS_RETURN_SUCCESS) {
                    memcpy(ctx->base.cookie, ext->data + 2, ext_cookie_len);
                    ctx->base.cookie_len = ext_cookie_len;
                    cookie_valid = 1;
                    noxtls_dtls_mark_validated(&ctx->base);
                }
            }
        }

        if(tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len) != NOXTLS_RETURN_SUCCESS) {
            free(record.data);
            return NOXTLS_RETURN_FAILED;
        }

        if(!cookie_valid) {
            if(noxtls_dtls_generate_cookie(&ctx->base, record.data, record.length, cookie, &cookie_len) != NOXTLS_RETURN_SUCCESS) {
                free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
        } else {
            memcpy(cookie, ctx->base.cookie, ctx->base.cookie_len);
            cookie_len = ctx->base.cookie_len;
        }

        if(!cookie_valid || (need_key_share && !has_key_share)) {
            if(has_key_share || !need_key_share) {
                selected_group = 0;
            }
            {
                uint32_t ext_remain = (offset < record.length) ? (record.length - offset) : 0U;
                noxtls_return_t cap_rc = tls13_hrr_first_ch_ext_order_capture(ctx, record.data + offset, ext_remain);
                if(cap_rc != NOXTLS_RETURN_SUCCESS) {
                    free(record.data);
                    return cap_rc;
                }
            }
            if(tls13_reset_transcript_for_hrr(ctx, hash_algo, hash_len) != NOXTLS_RETURN_SUCCESS) {
                free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            if(tls13_send_hello_retry_request_dtls(ctx, cookie, (uint16_t)cookie_len,
                                                   selected_group, hrr_msg, &hrr_len) != NOXTLS_RETURN_SUCCESS) {
                free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            tls13_append_handshake_message(ctx, hrr_msg, hrr_len);
            ctx->awaiting_hrr_client_hello = 1U;
            ctx->sent_hrr = 1U;
            free(record.data);
            return NOXTLS_RETURN_TIMEOUT;
        }
    }
#endif /* NOXTLS_FEATURE_DTLS */

    if(ctx->sent_hrr) {
        /* After HRR, append the second ClientHello only after binder verification succeeds. */
        tls13_append_handshake_message(ctx, record.data, record.length);
    }

    free(record.data);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Server: send ServerHello and derive handshake traffic keys from the shared secret.
 * @param[in,out] ctx Server context after ClientHello has been processed.
 * @return `NOXTLS_RETURN_SUCCESS` on success; key generation, encoding, or send error otherwise.
 */
noxtls_return_t noxtls_tls13_send_server_hello(tls13_context_t *ctx)
{
    uint64_t stage_t0;

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
    
    /* Generate server random */
    if(drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    if(drbg_generate(&drbg_state, ctx->server_random, sizeof(ctx->server_random) * 8U, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Build Server Hello noxtls_message */
    server_hello[offset++] = TLS_HANDSHAKE_SERVER_HELLO;
    server_hello[offset++] = 0x00;  /* Length (3 bytes) - placeholder */
    server_hello[offset++] = 0x00;
    server_hello[offset++] = 0x00;
    
    /* Version */
    if(tls13_is_dtls(ctx)) {
        server_hello[offset++] = (DTLS_VERSION_1_2 >> 8) & 0xFF;
        server_hello[offset++] = DTLS_VERSION_1_2 & 0xFF;
    } else {
        /* RFC 8446: legacy_version in ServerHello is 0x0303 (TLS 1.2). */
        server_hello[offset++] = (TLS_VERSION_1_2 >> 8) & 0xFF;
        server_hello[offset++] = TLS_VERSION_1_2 & 0xFF;
    }
    
    /* Random (32 bytes) */
    memcpy(server_hello + offset, ctx->server_random, TLS_RANDOM_SIZE);
    offset += TLS_RANDOM_SIZE;
    
    /* RFC 8446: echo ClientHello legacy_session_id exactly. */
    server_hello[offset++] = ctx->client_legacy_session_id_len;
    if(ctx->client_legacy_session_id_len > 0) {
        memcpy(server_hello + offset, ctx->client_legacy_session_id, ctx->client_legacy_session_id_len);
        offset += ctx->client_legacy_session_id_len;
    }
    noxtls_debug_printf("[TLS13_DEBUG] server_legacy_session_id_echo_len=%u\n", ctx->client_legacy_session_id_len);
    
    /* Cipher suite (2 bytes) */
    server_hello[offset++] = (ctx->cipher_suite >> 8) & 0xFF;
    server_hello[offset++] = ctx->cipher_suite & 0xFF;
    
    /* Compression method (1 byte) */
    server_hello[offset++] = 0x00;  /* NULL compression */

    /* Extensions length (2 bytes) placeholder */
    uint32_t extensions_start = offset;
    server_hello[offset++] = 0x00;
    server_hello[offset++] = 0x00;

    /* Supported Versions */
    server_hello[offset++] = (TLS_EXTENSION_SUPPORTED_VERSIONS >> 8) & 0xFF;
    server_hello[offset++] = TLS_EXTENSION_SUPPORTED_VERSIONS & 0xFF;
    server_hello[offset++] = 0x00;
    server_hello[offset++] = 0x02;
    if(tls13_is_dtls(ctx)) {
        server_hello[offset++] = (DTLS_VERSION_1_3 >> 8) & 0xFF;
        server_hello[offset++] = DTLS_VERSION_1_3 & 0xFF;
    } else {
        server_hello[offset++] = (TLS_VERSION_1_3 >> 8) & 0xFF;
        server_hello[offset++] = TLS_VERSION_1_3 & 0xFF;
    }

    if(!ctx->psk_in_use || ctx->psk_use_ecdhe) {
        tls_ecdhe_context_t *ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
        uint16_t selected_group = tls13_select_server_group(ctx);
        uint8_t *key_share_entry = (ctx->handshake_workspace != NULL) ? (ctx->handshake_workspace + TLS_SERVER_HELLO_DEFAULT_SIZE) : (uint8_t*)noxtls_malloc(TLS_KEY_SHARE_ENTRY_MAX_LEN);
        uint32_t key_share_entry_len = TLS_KEY_SHARE_ENTRY_MAX_LEN;
        const tls13_key_share_entry_t *client_share = NULL;
        uint32_t i;

        for(i = 0; i < ctx->client_key_shares_count; i++) {
            if(ctx->client_key_shares[i].group == selected_group) {
                client_share = &ctx->client_key_shares[i];
                break;
            }
        }
        ctx->selected_kex_group = selected_group;
        ctx->selected_kex_is_hybrid = tls13_group_is_hybrid(selected_group) ? 1U : 0U;
        ctx->selected_mlkem_param = tls13_group_mlkem_param(selected_group);
        ctx->last_accept_timing.send_server_hello_key_share_gen_us = 0U;

        if(selected_group == 0 || key_share_entry == NULL || client_share == NULL) {
            noxtls_debug_printf("[TLS13_DEBUG] send_server_hello: no compatible client key_share group found\n");
            if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_NOT_SUPPORTED;
        }

        if(tls13_group_is_mlkem(selected_group) || tls13_group_is_hybrid(selected_group)) {
#if NOXTLS_FEATURE_ML_KEM
            noxtls_mlkem_param_t mlkem_param = tls13_group_mlkem_param(selected_group);
            uint8_t pq_ss[NOXTLS_MLKEM_SHARED_SECRET_LEN];
            uint8_t pq_ct[NOXTLS_MLKEM_MAX_CIPHERTEXT_LEN];
            uint32_t pq_ct_len = noxtls_mlkem_ciphertext_len(mlkem_param);
            if(mlkem_param == 0 || pq_ct_len == 0) {
                if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
                if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return NOXTLS_RETURN_FAILED;
            }
            if(tls13_group_is_mlkem(selected_group)) {
                if(noxtls_mlkem_encaps(mlkem_param, client_share->key_exchange, pq_ct, pq_ss) != NOXTLS_RETURN_SUCCESS ||
                   4U + pq_ct_len > key_share_entry_len) {
                    if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
                    if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                    return NOXTLS_RETURN_FAILED;
                }
                tls13_write_uint16(key_share_entry, selected_group);
                tls13_write_uint16(key_share_entry + 2U, (uint16_t)pq_ct_len);
                memcpy(key_share_entry + 4U, pq_ct, pq_ct_len);
                key_share_entry_len = 4U + pq_ct_len;
                memcpy(ctx->hybrid_shared_secret, pq_ss, NOXTLS_MLKEM_SHARED_SECRET_LEN);
                ctx->hybrid_shared_secret_len = NOXTLS_MLKEM_SHARED_SECRET_LEN;
            } else {
                uint16_t x_len;
                uint16_t pk_len;
                const uint8_t *x_pub;
                const uint8_t *pk_pub;
                uint8_t classical_secret[NOXTLS_X25519_KEY_SIZE];
                uint32_t body_len;
                if(selected_group == TLS_NAMED_GROUP_X25519_MLKEM768) {
                    uint32_t pk_expected_len = noxtls_mlkem_public_key_len(mlkem_param);
                    if(pk_expected_len == 0 || client_share->key_exchange_len != (uint16_t)(NOXTLS_X25519_KEY_SIZE + pk_expected_len)) {
                        if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
                        if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                        return NOXTLS_RETURN_FAILED;
                    }
                    x_len = NOXTLS_X25519_KEY_SIZE;
                    pk_len = (uint16_t)pk_expected_len;
                    pk_pub = client_share->key_exchange;
                    x_pub = client_share->key_exchange + pk_expected_len;
                } else {
                    if(client_share->key_exchange_len < 4U) {
                        if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
                        if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                        return NOXTLS_RETURN_FAILED;
                    }
                    x_len = tls13_read_uint16(client_share->key_exchange);
                    if(client_share->key_exchange_len < 2U + x_len + 2U) {
                        if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
                        if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                        return NOXTLS_RETURN_FAILED;
                    }
                    x_pub = client_share->key_exchange + 2U;
                    pk_len = tls13_read_uint16(client_share->key_exchange + 2U + x_len);
                    if(client_share->key_exchange_len < 2U + x_len + 2U + pk_len) {
                        if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
                        if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                        return NOXTLS_RETURN_FAILED;
                    }
                    pk_pub = client_share->key_exchange + 2U + x_len + 2U;
                }
                if(ecdhe_ctx == NULL) {
                    ecdhe_ctx = (tls_ecdhe_context_t*)malloc(sizeof(tls_ecdhe_context_t));
                    if(ecdhe_ctx == NULL) {
                        if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
                        if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                        return NOXTLS_RETURN_FAILED;
                    }
                    ctx->ecdhe_ctx = ecdhe_ctx;
                } else {
                    noxtls_tls_ecdhe_context_free(ecdhe_ctx);
                }
                if(noxtls_tls_ecdhe_context_init(ecdhe_ctx, TLS_NAMED_GROUP_X25519) != NOXTLS_RETURN_SUCCESS ||
                   noxtls_tls_ecdhe_generate_ephemeral_key(ecdhe_ctx) != NOXTLS_RETURN_SUCCESS ||
                   x_len != NOXTLS_X25519_KEY_SIZE ||
                   noxtls_tls_ecdhe_compute_shared_secret_x25519(ecdhe_ctx, x_pub) != NOXTLS_RETURN_SUCCESS ||
                   noxtls_mlkem_encaps(mlkem_param, pk_pub, pq_ct, pq_ss) != NOXTLS_RETURN_SUCCESS) {
                    if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
                    if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                    return NOXTLS_RETURN_FAILED;
                }
                memcpy(classical_secret, ecdhe_ctx->shared_secret, ecdhe_ctx->shared_secret_len);
                if(tls13_combine_hybrid_secrets(ctx, classical_secret, ecdhe_ctx->shared_secret_len, pq_ss, NOXTLS_MLKEM_SHARED_SECRET_LEN) != NOXTLS_RETURN_SUCCESS) {
                    if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
                    if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                    return NOXTLS_RETURN_FAILED;
                }
                if(selected_group == TLS_NAMED_GROUP_X25519_MLKEM768) {
                    body_len = (uint32_t)(NOXTLS_X25519_KEY_SIZE + pq_ct_len);
                } else {
                    body_len = (uint32_t)(2U + NOXTLS_X25519_KEY_SIZE + 2U + pq_ct_len);
                }
                if(4U + body_len > key_share_entry_len) {
                    if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
                    if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                    return NOXTLS_RETURN_FAILED;
                }
                tls13_write_uint16(key_share_entry, selected_group);
                tls13_write_uint16(key_share_entry + 2U, (uint16_t)body_len);
                if(selected_group == TLS_NAMED_GROUP_X25519_MLKEM768) {
                    memcpy(key_share_entry + 4U, pq_ct, pq_ct_len);
                    memcpy(key_share_entry + 4U + pq_ct_len, ecdhe_ctx->x25519_public_key, NOXTLS_X25519_KEY_SIZE);
                } else {
                    tls13_write_uint16(key_share_entry + 4U, NOXTLS_X25519_KEY_SIZE);
                    memcpy(key_share_entry + 6U, ecdhe_ctx->x25519_public_key, NOXTLS_X25519_KEY_SIZE);
                    tls13_write_uint16(key_share_entry + 6U + NOXTLS_X25519_KEY_SIZE, (uint16_t)pq_ct_len);
                    memcpy(key_share_entry + 8U + NOXTLS_X25519_KEY_SIZE, pq_ct, pq_ct_len);
                }
                key_share_entry_len = 4U + body_len;
            }
#else
            if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
            if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
#endif
        } else if(tls13_group_is_ffdhe(selected_group)) {
            const uint8_t *p = NULL;
            const uint8_t *g = NULL;
            uint32_t p_len = 0;
            uint8_t server_private[NOXTLS_FFDHE8192_P_BYTES];
            uint8_t server_public[NOXTLS_FFDHE8192_P_BYTES];
            uint8_t client_public[NOXTLS_FFDHE8192_P_BYTES];

            if(client_share->key_exchange_len == 0 ||
               noxtls_dh_ffdhe_params(selected_group, &p, &g, &p_len) != NOXTLS_RETURN_SUCCESS ||
               p_len == 0 || p_len > NOXTLS_FFDHE8192_P_BYTES ||
               client_share->key_exchange_len > p_len) {
                if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
                if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return NOXTLS_RETURN_FAILED;
            }
            memset(server_private, 0, sizeof(server_private));
            memset(server_public, 0, sizeof(server_public));
            memset(client_public, 0, sizeof(client_public));
            memcpy(client_public + (p_len - client_share->key_exchange_len),
                   client_share->key_exchange,
                   client_share->key_exchange_len);
            if(noxtls_dh_ffdhe_generate_ephemeral(selected_group, server_private, server_public) != NOXTLS_RETURN_SUCCESS ||
               noxtls_dh_shared_secret(server_private, p_len, client_public, p_len, p, p_len,
                                       ctx->ffdhe_shared_secret) != NOXTLS_RETURN_SUCCESS ||
               4U + p_len > key_share_entry_len) {
                if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
                if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return NOXTLS_RETURN_FAILED;
            }
            ctx->ffdhe_shared_secret_len = p_len;
            tls13_write_uint16(key_share_entry, selected_group);
            tls13_write_uint16(key_share_entry + 2U, (uint16_t)p_len);
            memcpy(key_share_entry + 4U, server_public, p_len);
            key_share_entry_len = 4U + p_len;
        } else {
            stage_t0 = tls13_profile_now_us();
            if(ecdhe_ctx == NULL || ecdhe_ctx->named_group != selected_group) {
                if(ecdhe_ctx != NULL) {
                    noxtls_tls_ecdhe_context_free(ecdhe_ctx);
                    free(ecdhe_ctx);
                }
                ecdhe_ctx = (tls_ecdhe_context_t*)malloc(sizeof(tls_ecdhe_context_t));
                if(ecdhe_ctx == NULL) {
                    if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
                    if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                    return NOXTLS_RETURN_FAILED;
                }
                if(noxtls_tls_ecdhe_context_init(ecdhe_ctx, selected_group) != NOXTLS_RETURN_SUCCESS ||
                   noxtls_tls_ecdhe_generate_ephemeral_key(ecdhe_ctx) != NOXTLS_RETURN_SUCCESS) {
                    noxtls_tls_ecdhe_context_free(ecdhe_ctx);
                    free(ecdhe_ctx);
                    if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
                    if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                    return NOXTLS_RETURN_FAILED;
                }
                ctx->ecdhe_ctx = ecdhe_ctx;
            }
            key_share_entry_len = TLS_KEY_SHARE_ENTRY_MAX_LEN;
            if(noxtls_tls13_key_share_encode(ecdhe_ctx, key_share_entry, &key_share_entry_len) != NOXTLS_RETURN_SUCCESS) {
                if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
                if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return NOXTLS_RETURN_FAILED;
            }
            ctx->last_accept_timing.send_server_hello_key_share_gen_us = tls13_profile_elapsed_us(stage_t0);
        }

        server_hello[offset++] = (TLS_EXTENSION_KEY_SHARE >> 8) & 0xFF;
        server_hello[offset++] = TLS_EXTENSION_KEY_SHARE & 0xFF;
        server_hello[offset++] = (key_share_entry_len >> 8) & 0xFF;
        server_hello[offset++] = key_share_entry_len & 0xFF;
        memcpy(server_hello + offset, key_share_entry, key_share_entry_len);
        offset += key_share_entry_len;
        if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
    }

    if(ctx->psk_in_use) {
        server_hello[offset++] = (TLS_EXTENSION_PRE_SHARED_KEY >> 8) & 0xFF;
        server_hello[offset++] = TLS_EXTENSION_PRE_SHARED_KEY & 0xFF;
        server_hello[offset++] = 0x00;
        server_hello[offset++] = 0x02;
        server_hello[offset++] = (uint8_t)(ctx->psk_selected_identity >> 8);
        server_hello[offset++] = (uint8_t)(ctx->psk_selected_identity & 0xFF);
    }

    /* Connection ID (RFC 9146/9147): DTLS 1.3 only; echo client's CID if present (store for record header) */
    {
        tls_extension_t *ext_cid = NULL;
        if(tls13_is_dtls(ctx) &&
           noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_CONNECTION_ID, &ext_cid) == NOXTLS_RETURN_SUCCESS &&
           ext_cid != NULL && ext_cid->length >= 1) {
            uint8_t cid_len = ext_cid->data[0];
            if(cid_len > 0 && cid_len <= 32 && ext_cid->length >= 1U + cid_len) {
                ctx->peer_connection_id_len = cid_len;
                memcpy(ctx->peer_connection_id, ext_cid->data + 1, cid_len);
                ctx->own_connection_id_len = cid_len;
                memcpy(ctx->own_connection_id, ctx->peer_connection_id, cid_len);  /* echo for simplicity */
            }
            server_hello[offset++] = (TLS_EXTENSION_CONNECTION_ID >> 8) & 0xFF;
            server_hello[offset++] = TLS_EXTENSION_CONNECTION_ID & 0xFF;
            server_hello[offset++] = 0x00;
            server_hello[offset++] = (uint8_t)(1 + ctx->peer_connection_id_len);
            server_hello[offset++] = ctx->peer_connection_id_len;
            if(ctx->peer_connection_id_len > 0) {
                memcpy(server_hello + offset, ctx->peer_connection_id, ctx->peer_connection_id_len);
                offset += ctx->peer_connection_id_len;
            }
        } else if(tls13_is_dtls(ctx) &&
                  noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_CONNECTION_ID, &ext_cid) == NOXTLS_RETURN_SUCCESS) {
            server_hello[offset++] = (TLS_EXTENSION_CONNECTION_ID >> 8) & 0xFF;
            server_hello[offset++] = TLS_EXTENSION_CONNECTION_ID & 0xFF;
            server_hello[offset++] = 0x00;
            server_hello[offset++] = 0x01;
            server_hello[offset++] = 0x00;  /* zero-length CID */
        }
    }

    /* Update extensions length */
    uint32_t extensions_len32 = offset - extensions_start - 2;
    if(extensions_len32 > UINT16_MAX) {
        return NOXTLS_RETURN_FAILED;
    }
    uint16_t extensions_len = (uint16_t)extensions_len32;
    server_hello[extensions_start] = (extensions_len >> 8) & 0xFF;
    server_hello[extensions_start + 1] = extensions_len & 0xFF;
    
    /* Update handshake noxtls_message length */
    uint32_t handshake_len = offset - 4;
    server_hello[1] = (handshake_len >> 16) & 0xFF;
    server_hello[2] = (handshake_len >> 8) & 0xFF;
    server_hello[3] = handshake_len & 0xFF;
    
    /* Append to transcript before deriving keys; server derives after this returns. */
    tls13_append_handshake_message(ctx, server_hello, offset);
    
    /* Send via record layer */
    stage_t0 = tls13_profile_now_us();
    noxtls_return_t rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, server_hello, offset);
    ctx->last_accept_timing.send_server_hello_record_send_us = tls13_profile_elapsed_us(stage_t0);
    if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return rc;
}

/**
 * @brief Server: send EncryptedExtensions (ALPN, early data limits, etc.) under handshake encryption.
 * @param[in,out] ctx Server context with handshake write keys installed.
 * @return `NOXTLS_RETURN_SUCCESS` on success; message build or encrypted send error otherwise.
 */
noxtls_return_t noxtls_tls13_send_encrypted_extensions(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
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
    uint32_t ext_len;
    
    /* Build Encrypted Extensions noxtls_message */
    encrypted_extensions[offset++] = TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS;
    encrypted_extensions[offset++] = 0x00;  /* Length (3 bytes) - placeholder */
    encrypted_extensions[offset++] = 0x00;
    encrypted_extensions[offset++] = 0x00;
    
    /* Extensions: early_data (0-RTT), RFC 8449 record_size_limit (only if offered by client) */
    ext_len = 0;
    if(ctx->psk_in_use && ctx->client_offered_early_data) {
        ext_len += 8;  /* type(2) + length(2) + max_early_data_size(4) */
    }
    tls_extension_t *ext_rsl_client = NULL;
    if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_RECORD_SIZE_LIMIT, &ext_rsl_client) == NOXTLS_RETURN_SUCCESS &&
       ext_rsl_client != NULL) {
        /* RFC 8449: record_size_limit = max plaintext we are willing to receive from client */
        ext_len += 6;  /* type(2) + length(2) + limit(2) */
    }
    if(ctx->negotiated_alpn_len > 0) {
        ext_len += (uint16_t)(4U + 2U + 1U + (uint32_t)ctx->negotiated_alpn_len);
    }
    encrypted_extensions[offset++] = (ext_len >> 8) & 0xFF;
    encrypted_extensions[offset++] = ext_len & 0xFF;
    if(ctx->psk_in_use && ctx->client_offered_early_data) {
        encrypted_extensions[offset++] = (TLS_EXTENSION_EARLY_DATA >> 8) & 0xFF;
        encrypted_extensions[offset++] = TLS_EXTENSION_EARLY_DATA & 0xFF;
        encrypted_extensions[offset++] = 0x00;
        encrypted_extensions[offset++] = 0x04;
        encrypted_extensions[offset++] = 0xFF;
        encrypted_extensions[offset++] = 0xFF;
        encrypted_extensions[offset++] = 0xFF;
        encrypted_extensions[offset++] = 0xFF;
    }
    if(ext_rsl_client != NULL) {
        uint16_t rsl = (ctx->record_size_limit_recv > 0) ? ctx->record_size_limit_recv : (uint16_t)TLS_MAX_RECORD_SIZE;
        encrypted_extensions[offset++] = (TLS_EXTENSION_RECORD_SIZE_LIMIT >> 8) & 0xFF;
        encrypted_extensions[offset++] = TLS_EXTENSION_RECORD_SIZE_LIMIT & 0xFF;
        encrypted_extensions[offset++] = 0x00;
        encrypted_extensions[offset++] = 0x02;
        encrypted_extensions[offset++] = (rsl >> 8) & 0xFF;
        encrypted_extensions[offset++] = rsl & 0xFF;
    }
    if(ctx->negotiated_alpn_len > 0) {
        uint32_t alpn_written = noxtls_tls_alpn_write_selected_extension(
            (const char *)ctx->negotiated_alpn,
            ctx->negotiated_alpn_len,
            encrypted_extensions + offset,
            512U - offset);
        if(alpn_written == 0) {
            if(encrypted_extensions != ctx->handshake_workspace) {
                NOXTLS_SECURE_FREE(encrypted_extensions, 512);
            } else if(ctx->handshake_workspace != NULL) {
                memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            }
            return NOXTLS_RETURN_FAILED;
        }
        offset += alpn_written;
    }
    
    /* Update handshake noxtls_message length */
    uint32_t handshake_len = offset - 4;
    encrypted_extensions[1] = (handshake_len >> 16) & 0xFF;
    encrypted_extensions[2] = (handshake_len >> 8) & 0xFF;
    encrypted_extensions[3] = handshake_len & 0xFF;
    
    {
        noxtls_return_t rc = tls13_send_handshake_message(ctx, encrypted_extensions, offset);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(encrypted_extensions != ctx->handshake_workspace) NOXTLS_SECURE_FREE(encrypted_extensions, 512); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return rc;
        }
    }
    tls13_append_handshake_message(ctx, encrypted_extensions, offset);
    if(encrypted_extensions != ctx->handshake_workspace) NOXTLS_SECURE_FREE(encrypted_extensions, 512); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Server: send CertificateRequest to solicit a client certificate (mutual TLS).
 * @param[in,out] ctx Server context with `request_client_auth` or `require_client_auth` set.
 * @return `NOXTLS_RETURN_SUCCESS` on success; send or encoding error otherwise.
 */
noxtls_return_t noxtls_tls13_send_certificate_request(tls13_context_t *ctx)
{
    static const uint16_t cert_req_sigalgs[] = {
        TLS_SIGSCHEME_ED25519,
        TLS_SIGSCHEME_ED448,
        0x0603, /* ecdsa_secp521r1_sha512 */
        TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384,
        TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256,
        0x0303, /* ecdsa_sha224 */
        0x0203, /* ecdsa_sha1 */
        0x0806, /* rsa_pss_rsae_sha512 */
        0x080B, /* rsa_pss_pss_sha512 */
        0x0805, /* rsa_pss_rsae_sha384 */
        0x080A, /* rsa_pss_pss_sha384 */
        TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256,
        0x0809, /* rsa_pss_pss_sha256 */
        0x0601, /* rsa_pkcs1_sha512 */
        0x0501, /* rsa_pkcs1_sha384 */
        0x0401, /* rsa_pkcs1_sha256 */
        0x0301, /* rsa_pkcs1_sha224 */
        0x0201  /* rsa_pkcs1_sha1 */
    };
    uint8_t cert_req[128];
    uint32_t offset = 0;
    uint32_t sigalgs_len = (uint32_t)(sizeof(cert_req_sigalgs));
    uint32_t i;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    /*
     * RFC 8446 4.3.2:
     * CertificateRequest includes certificate_request_context and extensions.
     * The signature_algorithms extension is required for certificate-based client auth.
     */
    cert_req[offset++] = TLS_HANDSHAKE_CERTIFICATE_REQUEST;
    cert_req[offset++] = 0x00;
    cert_req[offset++] = 0x00;
    cert_req[offset++] = 0x00; /* handshake len placeholder */
    cert_req[offset++] = 0x00;  /* certificate_request_context length 0 */

    /*
     * extensions length:
     *   2 (ext type) + 2 (ext len) + 2 (sig list len) + N (sig list bytes)
     */
    {
        uint16_t ext_block_len = (uint16_t)(2U + 2U + 2U + sigalgs_len);
        cert_req[offset++] = (uint8_t)(ext_block_len >> 8);
        cert_req[offset++] = (uint8_t)(ext_block_len & 0xFF);
    }

    /* extension type signature_algorithms (0x000d) */
    cert_req[offset++] = 0x00;
    cert_req[offset++] = TLS_EXTENSION_SIGNATURE_ALGORITHMS;
    cert_req[offset++] = (uint8_t)(((uint16_t)(2U + sigalgs_len)) >> 8);
    cert_req[offset++] = (uint8_t)(((uint16_t)(2U + sigalgs_len)) & 0xFF);

    /* SignatureScheme vector length */
    cert_req[offset++] = (uint8_t)(((uint16_t)sigalgs_len) >> 8);
    cert_req[offset++] = (uint8_t)(((uint16_t)sigalgs_len) & 0xFF);

    for(i = 0; i < (uint32_t)(sizeof(cert_req_sigalgs) / sizeof(cert_req_sigalgs[0])); i++) {
        cert_req[offset++] = (uint8_t)(cert_req_sigalgs[i] >> 8);
        cert_req[offset++] = (uint8_t)(cert_req_sigalgs[i] & 0xFF);
    }

    {
        uint32_t hs_len = offset - 4U;
        cert_req[1] = (uint8_t)(hs_len >> 16);
        cert_req[2] = (uint8_t)(hs_len >> 8);
        cert_req[3] = (uint8_t)(hs_len & 0xFF);
    }

    {
        noxtls_return_t rc = tls13_send_handshake_message(ctx, cert_req, offset);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    tls13_append_handshake_message(ctx, cert_req, offset);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Server: send Certificate message from the configured server chain.
 * @param[in,out] ctx Server context with server certificate configured.
 * @return `NOXTLS_RETURN_SUCCESS` on success; error if no certificate or send failure.
 */
noxtls_return_t noxtls_tls13_send_certificate(tls13_context_t *ctx)
{
    uint32_t cert_list_len;
    uint32_t i;
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
    
    /* Build Certificate noxtls_message */
    certificate[offset++] = TLS_HANDSHAKE_CERTIFICATE;
    certificate[offset++] = 0x00;  /* Length (3 bytes) - placeholder */
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;
    
    /* Certificate request context (1 byte) - empty for server */
    certificate[offset++] = 0x00;
    
    if(ctx->server_cert_len > (uint32_t)(UINT32_MAX - 3U)) {
        tls13_release_handshake_cert_buffer(ctx, certificate);
        return NOXTLS_RETURN_FAILED;
    }
    /* Certificate list length (3 bytes): leaf + optional intermediates */
    cert_list_len = ctx->server_cert_len + 5U;  /* +3 entry length +2 entry extensions length */
    for(i = 0; i < ctx->server_cert_chain_count; i++) {
        if(ctx->server_cert_chain == NULL || ctx->server_cert_chain_len == NULL) {
            tls13_release_handshake_cert_buffer(ctx, certificate);
            return NOXTLS_RETURN_FAILED;
        }
        if(ctx->server_cert_chain[i] == NULL || ctx->server_cert_chain_len[i] == 0U) {
            tls13_release_handshake_cert_buffer(ctx, certificate);
            return NOXTLS_RETURN_FAILED;
        }
        cert_list_len += 5U + ctx->server_cert_chain_len[i];
    }
    certificate[offset++] = (cert_list_len >> 16) & 0xFF;
    certificate[offset++] = (cert_list_len >> 8) & 0xFF;
    certificate[offset++] = cert_list_len & 0xFF;
    
    /* Certificate entry length (3 bytes) */
    certificate[offset++] = (ctx->server_cert_len >> 16) & 0xFF;
    certificate[offset++] = (ctx->server_cert_len >> 8) & 0xFF;
    certificate[offset++] = ctx->server_cert_len & 0xFF;
    
    /* Certificate data + trailing extensions length (2 bytes) */
    if(offset > TLS_HANDSHAKE_WORKSPACE_SIZE ||
       (TLS_HANDSHAKE_WORKSPACE_SIZE - offset) < 2U ||
       ctx->server_cert_len > (TLS_HANDSHAKE_WORKSPACE_SIZE - offset - 2U)) {
        tls13_release_handshake_cert_buffer(ctx, certificate);
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(certificate + offset, ctx->server_cert, ctx->server_cert_len);
    offset += ctx->server_cert_len;
    
    /* Extensions length (2 bytes) - no extensions */
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;

    for(i = 0; i < ctx->server_cert_chain_count; i++) {
        uint32_t chain_len = ctx->server_cert_chain_len[i];
        certificate[offset++] = (chain_len >> 16) & 0xFF;
        certificate[offset++] = (chain_len >> 8) & 0xFF;
        certificate[offset++] = chain_len & 0xFF;
        if(offset > TLS_HANDSHAKE_WORKSPACE_SIZE ||
           (TLS_HANDSHAKE_WORKSPACE_SIZE - offset) < 2U ||
           chain_len > (TLS_HANDSHAKE_WORKSPACE_SIZE - offset - 2U)) {
            tls13_release_handshake_cert_buffer(ctx, certificate);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(certificate + offset, ctx->server_cert_chain[i], chain_len);
        offset += chain_len;
        certificate[offset++] = 0x00;
        certificate[offset++] = 0x00;
    }
    
    /* Update handshake noxtls_message length */
    uint32_t handshake_len = offset - 4;
    certificate[1] = (handshake_len >> 16) & 0xFF;
    certificate[2] = (handshake_len >> 8) & 0xFF;
    certificate[3] = handshake_len & 0xFF;
    
    {
        noxtls_return_t rc = tls13_send_handshake_message(ctx, certificate, offset);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            tls13_release_handshake_cert_buffer(ctx, certificate);
            return rc;
        }
    }
    tls13_append_handshake_message(ctx, certificate, offset);
    tls13_release_handshake_cert_buffer(ctx, certificate);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Server: sign the handshake transcript and send CertificateVerify.
 * @param[in,out] ctx Server context with server private key for the selected certificate.
 * @return `NOXTLS_RETURN_SUCCESS` on success; signing or send error otherwise.
 */
noxtls_return_t noxtls_tls13_send_certificate_verify(tls13_context_t *ctx)
{
    tls13_cv_msg_buf_t cv_msg;
    uint32_t offset = 0;
    static const char ctx_str[] = "TLS 1.3, server CertificateVerify";
    uint8_t to_sign[64 + sizeof(ctx_str) + 1 + 64];
    uint32_t to_sign_len;
    noxtls_return_t rc;
    uint32_t signature_len = 0;
    uint16_t selected_sig_scheme = 0;
    uint64_t stage_t0;

    memset(&cv_msg, 0, sizeof(cv_msg));

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    if(ctx->server_private_rsa == NULL &&
       ctx->server_private_ecdsa == NULL &&
       !ctx->server_cert_use_ed25519 &&
       !ctx->server_cert_use_ed448 &&
       !ctx->server_cert_use_mldsa &&
       !ctx->server_cert_use_slhdsa) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Pick SignatureScheme before building Transcript-Hash (RFC 8446 §4.4.3). */
    if(ctx->server_cert_use_mldsa) {
#if NOXTLS_FEATURE_ML_DSA
        selected_sig_scheme = (ctx->server_private_mldsa_param == NOXTLS_MLDSA_44) ? TLS_SIGSCHEME_MLDSA44 :
                              (ctx->server_private_mldsa_param == NOXTLS_MLDSA_65) ? TLS_SIGSCHEME_MLDSA65 :
                              TLS_SIGSCHEME_MLDSA87;
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else if(ctx->server_cert_use_slhdsa) {
#if NOXTLS_FEATURE_SLH_DSA
        selected_sig_scheme = tls13_slhdsa_param_to_sig_scheme(ctx->server_private_slhdsa_param);
        if(selected_sig_scheme == 0U ||
           !tls13_client_supports_signature_scheme(ctx, selected_sig_scheme)) 
        {
            return NOXTLS_RETURN_FAILED;
        }
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else {
        selected_sig_scheme = tls13_select_server_certificate_sig_scheme(ctx);
        if(selected_sig_scheme == 0U) {
            return NOXTLS_RETURN_FAILED;
        }
        if(!tls13_client_supports_signature_scheme(ctx, selected_sig_scheme)) 
        {
            return NOXTLS_RETURN_FAILED;
        }
    }

    rc = tls13_cv_msg_buf_init(&cv_msg, selected_sig_scheme);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    signature_len = cv_msg.cap - 8U;

    stage_t0 = tls13_profile_now_us();
    rc = tls13_build_certificate_verify_tosign(ctx, selected_sig_scheme, ctx_str,
                                             (uint32_t)(sizeof(ctx_str) - 1U),
                                             to_sign, &to_sign_len);
    ctx->last_accept_timing.send_certificate_verify_build_tosign_us = tls13_profile_elapsed_us(stage_t0);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        tls13_cv_msg_buf_free(&cv_msg);
        return rc;
    }

    cv_msg.buf[offset++] = TLS_HANDSHAKE_CERTIFICATE_VERIFY;
    cv_msg.buf[offset++] = 0x00;
    cv_msg.buf[offset++] = 0x00;
    cv_msg.buf[offset++] = 0x00;
    /* NOLINTNEXTLINE(bugprone-branch-clone): branch shape is intentionally parallel across signature algorithms. */
    stage_t0 = tls13_profile_now_us();
    if(ctx->server_cert_use_mldsa) {
#if NOXTLS_FEATURE_ML_DSA
        rc = noxtls_mldsa_sign(ctx->server_private_mldsa_param, ctx->server_private_mldsa,
                               to_sign, to_sign_len, cv_msg.buf + 8, &signature_len);
#else
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
        goto cv_exit;
#endif
    } else if(ctx->server_cert_use_slhdsa) {
#if NOXTLS_FEATURE_SLH_DSA
        rc = noxtls_slhdsa_sign(ctx->server_private_slhdsa_param,
                                ctx->server_private_slhdsa,
                                to_sign,
                                to_sign_len,
                                cv_msg.buf + 8,
                                &signature_len);
#else
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
        goto cv_exit;
#endif
    } else {
        if(ctx->server_private_ecdsa != NULL) {
            ecc_key_t *eckey = (ecc_key_t *)ctx->server_private_ecdsa;
            uint32_t coord_size = eckey->curve != NULL ? eckey->curve->size : 32U;
            noxtls_hash_algos_t verify_hash;
            ecdsa_signature_t sig;
            uint32_t der_len;

            if(!tls13_ecdsa_sig_scheme_to_hash(selected_sig_scheme, &verify_hash)) {
                rc = NOXTLS_RETURN_INVALID_ALGORITHM;
                goto cv_exit;
            }
            rc = noxtls_ecdsa_signature_init(&sig, coord_size);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                goto cv_exit;
            }
            rc = noxtls_ecdsa_sign(eckey, to_sign, to_sign_len, &sig, verify_hash);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_debug_printf("[TLS_DEBUG] certificate_verify: ecdsa_sign failed rc=%d\n", (int)rc);
                noxtls_ecdsa_signature_free(&sig);
                goto cv_exit;
            }
            ctx->last_accept_timing.send_certificate_verify_sign_us = tls13_profile_elapsed_us(stage_t0);
            stage_t0 = tls13_profile_now_us();
            der_len = tls13_ecdsa_signature_to_der(&sig, cv_msg.buf + 8, cv_msg.cap - 8U);
            noxtls_ecdsa_signature_free(&sig);
            ctx->last_accept_timing.send_certificate_verify_der_encode_us = tls13_profile_elapsed_us(stage_t0);
            if(der_len == 0) {
                rc = NOXTLS_RETURN_FAILED;
                goto cv_exit;
            }
            signature_len = der_len;
        } else if(ctx->server_cert_use_ed25519) {
            if(selected_sig_scheme != TLS_SIGSCHEME_ED25519) {
                rc = NOXTLS_RETURN_FAILED;
                goto cv_exit;
            }
            rc = noxtls_ed25519_sign(ctx->server_private_ed25519, to_sign, to_sign_len, cv_msg.buf + 8);
            signature_len = 64;
        } else if(ctx->server_cert_use_ed448) {
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
            if(selected_sig_scheme != TLS_SIGSCHEME_ED448) {
                rc = NOXTLS_RETURN_FAILED;
                goto cv_exit;
            }
            rc = noxtls_ed448_sign(ctx->server_private_ed448, to_sign, to_sign_len, cv_msg.buf + 8);
            signature_len = 114;
#else
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
            goto cv_exit;
#endif
        } else if(ctx->server_private_rsa != NULL) {
            noxtls_hash_algos_t rsa_hash = NOXTLS_HASH_SHA_256;
            if(selected_sig_scheme == 0x0805u) {
                rsa_hash = NOXTLS_HASH_SHA_384;
            } else if(selected_sig_scheme == 0x0806u) {
                rsa_hash = NOXTLS_HASH_SHA_512;
            }
            rc = noxtls_rsa_sign_pss((const rsa_key_t *)ctx->server_private_rsa, to_sign, to_sign_len,
                                     cv_msg.buf + 8, &signature_len, rsa_hash);
        } else {
            rc = NOXTLS_RETURN_FAILED;
            goto cv_exit;
        }
    }
    if(ctx->server_private_ecdsa == NULL) {
        ctx->last_accept_timing.send_certificate_verify_sign_us = tls13_profile_elapsed_us(stage_t0);
        ctx->last_accept_timing.send_certificate_verify_der_encode_us = 0U;
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cv_exit;
    }
    cv_msg.buf[offset++] = (uint8_t)(selected_sig_scheme >> 8);
    cv_msg.buf[offset++] = (uint8_t)(selected_sig_scheme & 0xFF);
    cv_msg.buf[offset++] = (uint8_t)((signature_len >> 8) & 0xFF);
    cv_msg.buf[offset++] = (uint8_t)(signature_len & 0xFF);
    offset += signature_len;
    {
        uint32_t handshake_len = offset - 4U;
        cv_msg.buf[1] = (uint8_t)((handshake_len >> 16) & 0xFF);
        cv_msg.buf[2] = (uint8_t)((handshake_len >> 8) & 0xFF);
        cv_msg.buf[3] = (uint8_t)(handshake_len & 0xFF);
    }
    stage_t0 = tls13_profile_now_us();
    rc = tls13_send_handshake_message(ctx, cv_msg.buf, offset);
    ctx->last_accept_timing.send_certificate_verify_record_send_us = tls13_profile_elapsed_us(stage_t0);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cv_exit;
    }
    tls13_append_handshake_message(ctx, cv_msg.buf, offset);
    rc = NOXTLS_RETURN_SUCCESS;

cv_exit:
    tls13_cv_msg_buf_free(&cv_msg);
    return rc;
}

/**
 * @brief Server: send Finished and derive application traffic secrets.
 * @param[in,out] ctx Server context after CertificateVerify has been sent.
 * @return `NOXTLS_RETURN_SUCCESS` on success; Finished build, send, or key derivation error otherwise.
 */
noxtls_return_t noxtls_tls13_send_finished_server(tls13_context_t *ctx)
{
    uint8_t finished[64];
    uint32_t offset = 0;
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    {
        uint8_t transcript_hash[64];
        uint32_t transcript_len = sizeof(transcript_hash);
        uint8_t finished_key[64];
        uint32_t verify_len;
        rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                                 transcript_hash, &transcript_len);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->server_handshake_traffic_secret, hash_len,
                                    (const uint8_t *)"finished", 8, NULL, 0,
                                    finished_key, hash_len);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        verify_len = hash_len;
        rc = noxtls_hmac_compute(hash_algo, finished_key, hash_len, transcript_hash, transcript_len,
                          finished + 4, &verify_len);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        finished[offset++] = TLS_HANDSHAKE_FINISHED;
        finished[offset++] = 0x00;
        finished[offset++] = 0x00;
        finished[offset++] = (uint8_t)verify_len;
        offset += verify_len;
        /* RFC 5929: store first Finished verify_data for tls-unique (TLS 1.3 server sends first) */
        if(ctx->channel_binding_first_finished_len == 0 && verify_len <= sizeof(ctx->channel_binding_first_finished)) {
            memcpy(ctx->channel_binding_first_finished, finished + 4, verify_len);
            ctx->channel_binding_first_finished_len = verify_len;
        }
    }
    {
        rc = tls13_send_handshake_message(ctx, finished, offset);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    /* Server Finished is included in transcript after sending. */
    tls13_append_handshake_message(ctx, finished, offset);
    ctx->app_secret_transcript_len = ctx->handshake_messages_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Server: receive and parse the client Certificate message (mutual TLS).
 * @param[in,out] ctx Server context with `request_client_auth` enabled.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_TLS_ALERT_CERTIFICATE_REQUIRED` if required but absent.
 */
noxtls_return_t tls13_recv_client_certificate(tls13_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    uint32_t offset;
    uint8_t ctx_len;
    uint32_t cert_list_len;
    uint32_t cert_len;
    uint32_t cert_list_start;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = tls13_recv_handshake_message(ctx, &msg, &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(msg_len < 4 || msg[0] != TLS_HANDSHAKE_CERTIFICATE) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    tls13_append_handshake_message(ctx, msg, msg_len);
    offset = 4;
    if(offset + 1 > msg_len) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    ctx_len = msg[offset++];
    if(offset + ctx_len + 3 > msg_len) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    offset += ctx_len;
    cert_list_len = (msg[offset] << 16) | (msg[offset + 1] << 8) | msg[offset + 2];
    offset += 3;
    cert_list_start = offset;
    if(cert_list_len == 0) {
        free(msg);
        return NOXTLS_RETURN_SUCCESS;  /* Client sent no certificate */
    }
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
    if(ctx->client_cert) {
        free(ctx->client_cert);
        ctx->client_cert = NULL;
    }
    ctx->client_cert = (uint8_t*)malloc(cert_len);
    if(ctx->client_cert == NULL) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(ctx->client_cert, msg + offset, cert_len);
    ctx->client_cert_len = cert_len;
    offset += cert_len;
    if(offset + 2U > msg_len) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    {
        uint16_t leaf_ext_len = ((uint16_t)msg[offset] << 8) | (uint16_t)msg[offset + 1];
        offset += 2U;
        if(offset + leaf_ext_len > msg_len) {
            free(msg);
            return NOXTLS_RETURN_FAILED;
        }
        offset += leaf_ext_len;
    }
    if(ctx->client_cert_parsed) {
        noxtls_x509_certificate_free((x509_certificate_t*)ctx->client_cert_parsed);
        free(ctx->client_cert_parsed);
        ctx->client_cert_parsed = NULL;
    }
    {
        x509_certificate_t *parsed = (x509_certificate_t*)malloc(sizeof(x509_certificate_t));
        if(parsed) {
            x509_certificate_chain_t presented_chain;
            uint32_t cert_list_end = cert_list_start + cert_list_len;
            noxtls_return_t parse_rc;
            if(noxtls_x509_certificate_chain_init(&presented_chain) != NOXTLS_RETURN_SUCCESS) {
                free(parsed);
                free(msg);
                return NOXTLS_RETURN_FAILED;
            }
            noxtls_x509_certificate_init(parsed);
            parse_rc = noxtls_x509_certificate_parse_der(parsed, ctx->client_cert, ctx->client_cert_len);
            if(parse_rc == NOXTLS_RETURN_SUCCESS) {
                while(offset + 3U <= cert_list_end) {
                    uint32_t issuer_len = ((uint32_t)msg[offset] << 16) |
                                          ((uint32_t)msg[offset + 1] << 8) |
                                          (uint32_t)msg[offset + 2];
                    x509_certificate_t issuer_cert;
                    uint16_t issuer_ext_len;
                    offset += 3U;
                    if(issuer_len == 0 || offset + issuer_len + 2U > cert_list_end) {
                        noxtls_x509_certificate_chain_free(&presented_chain);
                        noxtls_x509_certificate_free(parsed);
                        free(parsed);
                        free(msg);
                        return NOXTLS_RETURN_FAILED;
                    }
                    noxtls_x509_certificate_init(&issuer_cert);
                    rc = noxtls_x509_certificate_parse_der(&issuer_cert, msg + offset, issuer_len);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        noxtls_x509_certificate_free(&issuer_cert);
                        noxtls_x509_certificate_chain_free(&presented_chain);
                        noxtls_x509_certificate_free(parsed);
                        free(parsed);
                        free(msg);
                        return rc;
                    }
                    rc = noxtls_x509_certificate_chain_add(&presented_chain, &issuer_cert);
                    noxtls_x509_certificate_free(&issuer_cert);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        noxtls_x509_certificate_chain_free(&presented_chain);
                        noxtls_x509_certificate_free(parsed);
                        free(parsed);
                        free(msg);
                        return rc;
                    }
                    offset += issuer_len;
                    issuer_ext_len = ((uint16_t)msg[offset] << 8) | (uint16_t)msg[offset + 1];
                    offset += 2U;
                    if(offset + issuer_ext_len > cert_list_end) {
                        noxtls_x509_certificate_chain_free(&presented_chain);
                        noxtls_x509_certificate_free(parsed);
                        free(parsed);
                        free(msg);
                        return NOXTLS_RETURN_FAILED;
                    }
                    offset += issuer_ext_len;
                }
                if(offset != cert_list_end) {
                    noxtls_x509_certificate_chain_free(&presented_chain);
                    noxtls_x509_certificate_free(parsed);
                    free(parsed);
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }
                /*
                 * TLS 1.3 requires proof-of-possession via CertificateVerify.
                 * Chain trust validation is policy-driven; enforce it only when
                 * trust anchors are configured.
                 */
                if(noxtls_x509_trust_store_has_anchors()) {
                    rc = noxtls_x509_verify_client_cert_trust_ex(parsed, &presented_chain,
                                                                 ctx->verify_crl, NULL);
                } else {
                    rc = NOXTLS_RETURN_SUCCESS;
                }
                noxtls_x509_certificate_chain_free(&presented_chain);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_x509_certificate_free(parsed);
                    free(parsed);
                    free(msg);
                    return rc;
                }
                ctx->client_cert_parsed = parsed;
            } else {
                noxtls_x509_certificate_free(parsed);
                free(parsed);
                noxtls_x509_certificate_chain_free(&presented_chain);
                free(msg);
                return parse_rc;
            }
        } else {
            free(msg);
            return NOXTLS_RETURN_FAILED;
        }
    }
    free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Server: receive client CertificateVerify and verify the signature over the transcript.
 * @param[in,out] ctx Server context with client certificate loaded (may be empty for optional auth).
 * @return `NOXTLS_RETURN_SUCCESS` on valid signature; verification or I/O error otherwise.
 */
noxtls_return_t tls13_recv_client_certificate_verify(tls13_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    uint8_t to_verify[64 + 32 + 1 + 64];
    uint32_t to_verify_len;
    noxtls_return_t rc;
    static const char ctx_str[] = "TLS 1.3, client CertificateVerify";
    uint16_t sig_scheme;
    uint16_t sig_len;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER || ctx->client_cert_parsed == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = tls13_recv_handshake_message(ctx, &msg, &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(msg_len < 8 || msg[0] != TLS_HANDSHAKE_CERTIFICATE_VERIFY) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }

    sig_scheme = (uint16_t)((msg[4] << 8) | msg[5]);
    sig_len = (uint16_t)((msg[6] << 8) | msg[7]);
    if(8U + sig_len > msg_len) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    rc = tls13_build_certificate_verify_tosign(ctx, sig_scheme, ctx_str,
                                             (uint32_t)(sizeof(ctx_str) - 1U),
                                             to_verify, &to_verify_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(msg);
        return rc;
    }

    {
        x509_certificate_t *cert = (x509_certificate_t *)ctx->client_cert_parsed;

        if(sig_scheme == TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256 ||
           sig_scheme == 0x0805u || /* rsa_pss_rsae_sha384 */
           sig_scheme == 0x0806u) { /* rsa_pss_rsae_sha512 */
            if(cert->rsa_modulus == NULL || cert->rsa_exponent == NULL) {
                free(msg);
                return NOXTLS_RETURN_FAILED;
            }
            {
                uint32_t mod_len;
                uint32_t exp_len;
                const uint8_t *mod_ptr;
                const uint8_t *exp_ptr;
                rsa_key_size_t key_size;
                rsa_key_t rsa_key;
                noxtls_hash_algos_t verify_hash = NOXTLS_HASH_SHA_256;
                uint32_t n_copy_len;
                uint32_t e_copy_len;
                mod_ptr = cert->rsa_modulus;
                mod_len = cert->rsa_modulus_len;
                exp_ptr = cert->rsa_exponent;
                exp_len = cert->rsa_exponent_len;
                if(mod_len > 0U && mod_ptr[0] == 0x00u) { mod_ptr++; mod_len--; }
                if(exp_len > 0U && exp_ptr[0] == 0x00u) { exp_ptr++; exp_len--; }
                if(mod_len == 128U) key_size = RSA_1024_BIT;
                else if(mod_len == 256u) key_size = RSA_2048_BIT;
                else if(mod_len == 384u) key_size = RSA_3072_BIT;
                else if(mod_len == 512U) key_size = RSA_4096_BIT;
                else {
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }
                if(sig_scheme == 0x0805u) {
                    verify_hash = NOXTLS_HASH_SHA_384;
                } else if(sig_scheme == 0x0806u) {
                    verify_hash = NOXTLS_HASH_SHA_512;
                }
                rc = noxtls_rsa_key_init(&rsa_key, key_size);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    free(msg);
                    return rc;
                }
                n_copy_len = (mod_len <= rsa_key.key_bytes) ? mod_len : rsa_key.key_bytes;
                e_copy_len = (exp_len <= rsa_key.key_bytes) ? exp_len : rsa_key.key_bytes;
                memset(rsa_key.n, 0, rsa_key.key_bytes);
                memset(rsa_key.e, 0, rsa_key.key_bytes);
                memcpy(rsa_key.n + rsa_key.key_bytes - n_copy_len,
                       mod_ptr + mod_len - n_copy_len,
                       n_copy_len);
                memcpy(rsa_key.e + rsa_key.key_bytes - e_copy_len,
                       exp_ptr + exp_len - e_copy_len,
                       e_copy_len);
                rc = noxtls_rsa_verify_pss(&rsa_key, to_verify, to_verify_len, msg + 8, sig_len, verify_hash);
                noxtls_rsa_key_free(&rsa_key);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    free(msg);
                    return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
                }
            }
        } else if(sig_scheme == 0x081Au /* ecdsa_brainpoolP256r1tls13_sha256 */ ||
                  sig_scheme == 0x081Bu /* ecdsa_brainpoolP384r1tls13_sha384 */ ||
                  sig_scheme == 0x081Cu /* ecdsa_brainpoolP512r1tls13_sha512 */ ||
                  sig_scheme == TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256 ||
                  sig_scheme == TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384 ||
                  sig_scheme == 0x0603u /* ecdsa_secp521r1_sha512 */) {
            if(cert->ecc_public_key == NULL || cert->ecc_public_key_len == 0) {
                free(msg);
                return NOXTLS_RETURN_INVALID_PARAM;
            }
            {
                void *pubkey = NULL;
                uint32_t key_type = 0;
                ecc_key_t *ecc_key;
                ecdsa_signature_t ecdsa_sig;
                uint32_t coord_size = 0;
                noxtls_hash_algos_t verify_hash = NOXTLS_HASH_SHA_256;
                if(sig_scheme == TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256 ||
                   sig_scheme == 0x081Au) {
                    coord_size = 32U;
                    verify_hash = NOXTLS_HASH_SHA_256;
                } else if(sig_scheme == TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384 ||
                          sig_scheme == 0x081Bu) {
                    coord_size = 48U;
                    verify_hash = NOXTLS_HASH_SHA_384;
                } else if(sig_scheme == 0x0603u || sig_scheme == 0x081Cu) {
                    coord_size = (sig_scheme == 0x0603u) ? 66u : 64U;
                    verify_hash = NOXTLS_HASH_SHA_512;
                } else {
                    free(msg);
                    return NOXTLS_RETURN_INVALID_PARAM;
                }

                if(sig_scheme == 0x0603u) {
                    coord_size = 66u;
                }

                rc = noxtls_x509_certificate_get_public_key(cert, &pubkey, &key_type);
                if(rc != NOXTLS_RETURN_SUCCESS || pubkey == NULL || key_type != 2) {
                    if(pubkey) free(pubkey);
                    free(msg);
                    return NOXTLS_RETURN_INVALID_PARAM;
                }
                ecc_key = (ecc_key_t *)pubkey;
                if(ecc_key->curve == NULL || ecc_key->curve->size != coord_size) {
                    noxtls_ecc_key_free(ecc_key);
                    free(ecc_key);
                    free(msg);
                    return NOXTLS_RETURN_INVALID_PARAM;
                }
                rc = noxtls_ecdsa_signature_init(&ecdsa_sig, coord_size);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_ecc_key_free(ecc_key);
                    free(ecc_key);
                    free(msg);
                    return rc;
                }
                rc = noxtls_ecdsa_signature_parse_der(msg + 8, (uint32_t)sig_len, &ecdsa_sig, coord_size);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_ecdsa_signature_free(&ecdsa_sig);
                    noxtls_ecc_key_free(ecc_key);
                    free(ecc_key);
                    free(msg);
                    return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
                }
                rc = noxtls_ecdsa_verify(ecc_key, to_verify, to_verify_len, &ecdsa_sig, verify_hash);
                noxtls_ecdsa_signature_free(&ecdsa_sig);
                noxtls_ecc_key_free(ecc_key);
                free(ecc_key);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    free(msg);
                    return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
                }
            }
        } else if(sig_scheme == TLS_SIGSCHEME_ED25519) {
            if(!cert->has_ed25519 || sig_len != 64) {
                free(msg);
                return NOXTLS_RETURN_FAILED;
            }
            rc = noxtls_ed25519_verify(cert->ed25519_public_key, to_verify, to_verify_len, msg + 8);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                free(msg);
                return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
            }
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
        } else if(sig_scheme == TLS_SIGSCHEME_ED448) {
            if(!cert->has_ed448 || sig_len != 114) {
                free(msg);
                return NOXTLS_RETURN_FAILED;
            }
            rc = noxtls_ed448_verify(cert->ed448_public_key, to_verify, to_verify_len, msg + 8);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                free(msg);
                return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
            }
#endif
        } else if(sig_scheme == TLS_SIGSCHEME_MLDSA44 || sig_scheme == TLS_SIGSCHEME_MLDSA65 || sig_scheme == TLS_SIGSCHEME_MLDSA87) {
#if NOXTLS_FEATURE_ML_DSA
            noxtls_mldsa_param_t p = (sig_scheme == TLS_SIGSCHEME_MLDSA44) ? NOXTLS_MLDSA_44 :
                                     (sig_scheme == TLS_SIGSCHEME_MLDSA65) ? NOXTLS_MLDSA_65 :
                                     NOXTLS_MLDSA_87;
            if(!cert->has_mldsa || cert->mldsa_param != p) {
                free(msg);
                return NOXTLS_RETURN_FAILED;
            }
            rc = noxtls_mldsa_verify(p, cert->mldsa_public_key, to_verify, to_verify_len, msg + 8, sig_len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                free(msg);
                return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
            }
#else
            free(msg);
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        } else if(sig_scheme >= TLS_SIGSCHEME_SLHDSA_SHA2_128S &&
                  sig_scheme <= TLS_SIGSCHEME_SLHDSA_SHAKE_256F) {
#if NOXTLS_FEATURE_SLH_DSA
            noxtls_slhdsa_param_t p = NOXTLS_SLHDSA_NONE;

            rc = tls13_slhdsa_sig_scheme_to_param(sig_scheme, &p);
            if(rc != NOXTLS_RETURN_SUCCESS || !cert->has_slhdsa || cert->slhdsa_param != p) {
                free(msg);
                return NOXTLS_RETURN_FAILED;
            }
            rc = noxtls_slhdsa_verify(p, cert->slhdsa_public_key, to_verify, to_verify_len, msg + 8, sig_len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                free(msg);
                return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
            }
#else
            free(msg);
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        } else {
            free(msg);
            return NOXTLS_RETURN_INVALID_PARAM;
        }
    }
    tls13_append_handshake_message(ctx, msg, msg_len);
    free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Server: receive client Finished, verify, and install application traffic keys.
 * @param[in,out] ctx Server context after server Finished has been sent.
 * @return `NOXTLS_RETURN_SUCCESS` when application keys are installed; verify or I/O error otherwise.
 */
noxtls_return_t noxtls_tls13_recv_finished_client(tls13_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    rc = tls13_recv_handshake_message(ctx, &msg, &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(msg_len < 4 || msg[0] != TLS_HANDSHAKE_FINISHED) {
        if(msg) free(msg);
        return NOXTLS_RETURN_BAD_DATA;
    }
    {
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
            free(msg);
            return rc;
        }
        rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                                transcript_hash, &transcript_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(msg);
            return rc;
        }
        rc = tls13_ctx_hkdf_expand_label(ctx, hash_algo, ctx->client_handshake_traffic_secret, hash_len,
                                     (const uint8_t *)"finished", 8, NULL, 0,
                                     finished_key, hash_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(msg);
            return rc;
        }
        verify_len = hash_len;
        rc = noxtls_hmac_compute(hash_algo, finished_key, hash_len, transcript_hash, transcript_len,
                         verify_data, &verify_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(msg);
            return rc;
        }
        if(msg_len != 4U + verify_len) {
            free(msg);
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(noxtls_secret_memcmp(msg + 4, verify_data, verify_len) != 0) {
            free(msg);
            return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
        }
    }
    tls13_append_handshake_message(ctx, msg, msg_len);
    free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Fold the ASCII character to lowercase
 *
 * @param[in] c The character to fold
 * @return The folded character
 */
static uint8_t tls13_sni_ascii_fold_lc(uint8_t c)
{
    if(c >= (uint8_t)'A' && c <= (uint8_t)'Z') {
        return (uint8_t)(c + 32U);
    }
    return c;
}

/**
 * @brief Check if the SNI is equal to the expected SNI
 *
 * @param[in] expect The expected SNI
 * @param[in] client The client SNI
 * @param[in] client_len The length of the client SNI
 * @return 1 if the SNI is equal to the expected SNI, 0 otherwise
 */
static int tls13_sni_eq_dns_case_insensitive(const char *expect, const char *client, uint16_t client_len)
{
    size_t elen;
    uint32_t i;

    if(expect == NULL || client == NULL || client_len == 0U) {
        return 0;
    }
    elen = strlen(expect);
    if(elen == 0U || elen != (size_t)client_len) {
        return 0;
    }
    for(i = 0; i < (uint32_t)elen; i++) {
        if(tls13_sni_ascii_fold_lc((uint8_t)expect[i]) != tls13_sni_ascii_fold_lc((uint8_t)client[i])) {
            return 0;
        }
    }
    return 1;
}

/**
 * @brief Server: maybe alert unrecognized SNI
 *
 * @param[in] ctx The context to maybe alert unrecognized SNI from
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, or NOXTLS_RETURN_TLS_ERROR if the SNI is unrecognized
 */
static noxtls_return_t tls13_server_maybe_alert_unrecognized_sni(tls13_context_t *ctx)
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
       ctx->client_extensions.sni->name_len == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(tls13_sni_eq_dns_case_insensitive(exp,
                                         ctx->client_extensions.sni->hostname,
                                         ctx->client_extensions.sni->name_len)) {
        return NOXTLS_RETURN_SUCCESS;
    }
    {
        uint8_t lvl = (ctx->server_expect_sni_fatal != 0U) ? TLS_ALERT_LEVEL_FATAL : TLS_ALERT_LEVEL_WARNING;
        noxtls_return_t arc = noxtls_tls_send_alert(&ctx->base.base, lvl, TLS_ALERT_UNRECOGNIZED_NAME);
        if(arc != NOXTLS_RETURN_SUCCESS) {
            return arc;
        }
        if(ctx->server_expect_sni_fatal != 0U) {
            return NOXTLS_RETURN_TLS_ERROR;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}



/**
 * @brief Get the last accept fail step
 *
 * @return The last accept fail step
 */
const char *noxtls_tls13_last_accept_fail_step(void)
{
    return s_tls13_last_accept_fail_step;
}

const char *noxtls_tls13_last_connect_fail_step(void)
{
    return s_tls13_last_connect_fail_step;
}

static void tls13_connect_log_fail(const tls13_context_t *ctx, const char *step, noxtls_return_t rc)
{
    if(ctx == NULL || step == NULL || rc == NOXTLS_RETURN_SUCCESS || rc == NOXTLS_RETURN_TIMEOUT) {
        return;
    }
    if((strcmp(step, "send_client_hello") == 0) &&
       (s_tls13_last_connect_fail_step[0] != '\0')) {
        return;
    }
    {
        size_t n = strlen(step);
        if(n >= sizeof(s_tls13_last_connect_fail_step)) {
            n = sizeof(s_tls13_last_connect_fail_step) - 1U;
        }
        memcpy(s_tls13_last_connect_fail_step, step, n);
        s_tls13_last_connect_fail_step[n] = '\0';
    }
    noxtls_debug_printf("[TLS_DEBUG] tls13_connect: %s failed rc=%d (state=%u cipher=0x%04x)\n",
                        step, (int)rc, (unsigned)ctx->base.base.state, (unsigned)ctx->cipher_suite);
}

static void tls13_accept_log_fail_detail(const tls13_context_t *ctx,
                                         const char *prefix,
                                         const char *detail,
                                         noxtls_return_t rc)
{
    if(ctx == NULL || prefix == NULL || detail == NULL || detail[0] == '\0') {
        return;
    }
    if(rc == NOXTLS_RETURN_SUCCESS || rc == NOXTLS_RETURN_TIMEOUT) {
        return;
    }
    {
        char step[sizeof(s_tls13_last_accept_fail_step)];
        int written = snprintf(step, sizeof(step), "%s/%s", prefix, detail);
        if(written <= 0) {
            return;
        }
        tls13_accept_log_fail(ctx, step, rc);
    }
}

/**
 * @brief Log the accept fail
 *
 * @param[in] ctx The context to log the accept fail from
 * @param[in] step The step to log the accept fail from
 * @param[in] rc The return code to log the accept fail from
 * @return void
 */
static void tls13_accept_log_fail(const tls13_context_t *ctx, const char *step, noxtls_return_t rc)
{
    if(ctx == NULL || step == NULL || rc == NOXTLS_RETURN_SUCCESS || rc == NOXTLS_RETURN_TIMEOUT) {
        return;
    }
    if((strcmp(step, "recv_client_hello") == 0) &&
       (s_tls13_last_accept_fail_step[0] != '\0')) {
        return;
    }
    {
        size_t n = strlen(step);
        if(n >= sizeof(s_tls13_last_accept_fail_step)) {
            n = sizeof(s_tls13_last_accept_fail_step) - 1U;
        }
        memcpy(s_tls13_last_accept_fail_step, step, n);
        s_tls13_last_accept_fail_step[n] = '\0';
    }
    noxtls_debug_printf("[TLS_DEBUG] tls13_accept: %s failed rc=%d (state=%u cipher=0x%04x)\n",
                        step, (int)rc, (unsigned)ctx->base.base.state, (unsigned)ctx->cipher_suite);
}

/**
 * @brief Server: run the full TLS 1.3 handshake through application key installation.
 * @param[in,out] ctx Initialized server context with credentials configured.
 * @return `NOXTLS_RETURN_SUCCESS` when the handshake completes; error from any server step.
 */
noxtls_return_t noxtls_tls13_accept(tls13_context_t *ctx)
{
    noxtls_return_t rc;
    uint64_t accept_t0;
    uint64_t step_t0;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }

    if(ctx->server_handshake_step == TLS13_SERVER_HS_STEP_NONE || ctx->base.base.state != TLS_STATE_HANDSHAKING) {
        s_tls13_last_accept_fail_step[0] = '\0';
        memset(&ctx->last_accept_timing, 0, sizeof(ctx->last_accept_timing));
        ctx->base.base.state = TLS_STATE_HANDSHAKING;
        ctx->peer_compat_ccs_seen = 0U;
        ctx->server_handshake_step = TLS13_SERVER_HS_STEP_RECV_CH;
        NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_START);
    }

    accept_t0 = tls13_profile_now_us();

    while(1) {
        switch((tls13_server_handshake_step_t)ctx->server_handshake_step) {
            case TLS13_SERVER_HS_STEP_RECV_CH:
                step_t0 = tls13_profile_now_us();
                NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_RECV_CH);
                rc = noxtls_tls13_recv_client_hello(ctx);
                if(rc == NOXTLS_RETURN_TIMEOUT && (tls13_is_dtls(ctx) || ctx->awaiting_hrr_client_hello)) {
                    ctx->awaiting_hrr_client_hello = 0;
                    ctx->last_accept_timing.recv_client_hello_us = tls13_profile_elapsed_us(step_t0);
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_CH, rc);
                    tls13_send_handshake_alert_for_error(ctx, rc);
                    tls13_accept_log_fail(ctx, "recv_client_hello", rc);
                    ctx->last_accept_timing.recv_client_hello_us = tls13_profile_elapsed_us(step_t0);
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_CH, rc);
                ctx->last_accept_timing.recv_client_hello_us = tls13_profile_elapsed_us(step_t0);
                ctx->server_handshake_step = TLS13_SERVER_HS_STEP_PICK_SERVER_IDENTITY;
                break;

            case TLS13_SERVER_HS_STEP_PICK_SERVER_IDENTITY:
                step_t0 = tls13_profile_now_us();
                tls13_pick_server_ecdsa_identity_from_matrix(ctx);
                ctx->last_accept_timing.pick_server_identity_us = tls13_profile_elapsed_us(step_t0);
                ctx->server_handshake_step = TLS13_SERVER_HS_STEP_SELECT_CERT_SIG_SCHEME;
                break;

            case TLS13_SERVER_HS_STEP_SELECT_CERT_SIG_SCHEME:
                step_t0 = tls13_profile_now_us();
                if(!ctx->psk_in_use && tls13_select_server_certificate_sig_scheme(ctx) == 0U) {
                    tls13_send_handshake_alert_for_error(ctx, NOXTLS_RETURN_FAILED);
                    tls13_accept_log_fail(ctx, "select_certificate_sig_scheme", NOXTLS_RETURN_FAILED);
                    ctx->last_accept_timing.select_certificate_sig_scheme_us = tls13_profile_elapsed_us(step_t0);
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return NOXTLS_RETURN_FAILED;
                }
                ctx->last_accept_timing.select_certificate_sig_scheme_us = tls13_profile_elapsed_us(step_t0);
                ctx->server_handshake_step = TLS13_SERVER_HS_STEP_SNI_CHECK;
                break;

            case TLS13_SERVER_HS_STEP_SNI_CHECK:
                step_t0 = tls13_profile_now_us();
                rc = tls13_server_maybe_alert_unrecognized_sni(ctx);
                ctx->last_accept_timing.sni_check_us = tls13_profile_elapsed_us(step_t0);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    tls13_accept_log_fail(ctx, "sni_check", rc);
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                ctx->server_handshake_step = TLS13_SERVER_HS_STEP_SEND_SH;
                break;

            case TLS13_SERVER_HS_STEP_SEND_SH:
                step_t0 = tls13_profile_now_us();
                NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_SEND_SH);
                rc = noxtls_tls13_send_server_hello(ctx);
                ctx->last_accept_timing.send_server_hello_us = tls13_profile_elapsed_us(step_t0);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_SH, rc);
                    tls13_send_handshake_alert_for_error(ctx, rc);
                    tls13_accept_log_fail(ctx, "send_server_hello", rc);
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_SH, rc);
                ctx->server_handshake_step = TLS13_SERVER_HS_STEP_SEND_MIDDLEBOX_CCS;
                break;

            case TLS13_SERVER_HS_STEP_SEND_MIDDLEBOX_CCS:
                if(!ctx->sent_hrr) {
                    step_t0 = tls13_profile_now_us();
                    rc = tls13_send_middlebox_compat_ccs(ctx);
                    ctx->last_accept_timing.send_middlebox_compat_ccs_us = tls13_profile_elapsed_us(step_t0);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        tls13_send_handshake_alert_for_error(ctx, rc);
                        ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                        return rc;
                    }
                } else {
                    ctx->last_accept_timing.send_middlebox_compat_ccs_us = 0U;
                }
                ctx->server_handshake_step = TLS13_SERVER_HS_STEP_PROCESS_CLIENT_SHARE;
                break;

            case TLS13_SERVER_HS_STEP_PROCESS_CLIENT_SHARE:
                step_t0 = tls13_profile_now_us();
                if(!ctx->psk_in_use || ctx->psk_use_ecdhe) {
                    rc = tls13_process_client_key_share_internal(ctx);
                    ctx->last_accept_timing.process_client_key_share_us = tls13_profile_elapsed_us(step_t0);
                } else {
                    rc = tls13_derive_handshake_keys(ctx, NULL, 0);
                    ctx->last_accept_timing.derive_handshake_keys_us = tls13_profile_elapsed_us(step_t0);
                }
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    tls13_send_handshake_alert_for_error(ctx, rc);
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                ctx->server_handshake_step = TLS13_SERVER_HS_STEP_SEND_ENCRYPTED_EXTENSIONS;
                break;

            case TLS13_SERVER_HS_STEP_SEND_ENCRYPTED_EXTENSIONS:
                step_t0 = tls13_profile_now_us();
                rc = noxtls_tls13_send_encrypted_extensions(ctx);
                ctx->last_accept_timing.send_encrypted_extensions_us = tls13_profile_elapsed_us(step_t0);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    tls13_send_handshake_alert_for_error(ctx, rc);
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                ctx->server_handshake_step = ctx->request_client_auth ?
                    TLS13_SERVER_HS_STEP_SEND_CERTIFICATE_REQUEST :
                    (!ctx->psk_in_use ? TLS13_SERVER_HS_STEP_SEND_CERTIFICATE : TLS13_SERVER_HS_STEP_SEND_FINISHED);
                break;

            case TLS13_SERVER_HS_STEP_SEND_CERTIFICATE_REQUEST:
                step_t0 = tls13_profile_now_us();
                rc = noxtls_tls13_send_certificate_request(ctx);
                ctx->last_accept_timing.send_certificate_request_us = tls13_profile_elapsed_us(step_t0);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    tls13_send_handshake_alert_for_error(ctx, rc);
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                ctx->server_handshake_step = !ctx->psk_in_use ?
                    TLS13_SERVER_HS_STEP_SEND_CERTIFICATE :
                    TLS13_SERVER_HS_STEP_SEND_FINISHED;
                break;

            case TLS13_SERVER_HS_STEP_SEND_CERTIFICATE:
                step_t0 = tls13_profile_now_us();
                rc = noxtls_tls13_send_certificate(ctx);
                ctx->last_accept_timing.send_certificate_us = tls13_profile_elapsed_us(step_t0);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    tls13_send_handshake_alert_for_error(ctx, rc);
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                ctx->server_handshake_step = TLS13_SERVER_HS_STEP_SEND_CERTIFICATE_VERIFY;
                break;

            case TLS13_SERVER_HS_STEP_SEND_CERTIFICATE_VERIFY:
                step_t0 = tls13_profile_now_us();
                rc = noxtls_tls13_send_certificate_verify(ctx);
                ctx->last_accept_timing.send_certificate_verify_us = tls13_profile_elapsed_us(step_t0);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    tls13_send_handshake_alert_for_error(ctx, rc);
                    tls13_accept_log_fail(ctx, "send_certificate_verify", rc);
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                ctx->server_handshake_step = TLS13_SERVER_HS_STEP_SEND_FINISHED;
                break;

            case TLS13_SERVER_HS_STEP_SEND_FINISHED:
                step_t0 = tls13_profile_now_us();
                NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED);
                rc = noxtls_tls13_send_finished_server(ctx);
                ctx->last_accept_timing.send_finished_us = tls13_profile_elapsed_us(step_t0);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED, rc);
                    tls13_send_handshake_alert_for_error(ctx, rc);
                    tls13_accept_log_fail(ctx, "send_finished", rc);
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED, rc);
                ctx->server_handshake_step = TLS13_SERVER_HS_STEP_DERIVE_APP_SECRETS;
                break;

            case TLS13_SERVER_HS_STEP_DERIVE_APP_SECRETS:
                step_t0 = tls13_profile_now_us();
                rc = tls13_derive_application_secrets(ctx);
                ctx->last_accept_timing.derive_application_secrets_us = tls13_profile_elapsed_us(step_t0);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    tls13_send_handshake_alert_for_error(ctx, rc);
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                ctx->server_handshake_step = TLS13_SERVER_HS_STEP_INSTALL_SERVER_APP_WRITE_KEYS;
                break;

            case TLS13_SERVER_HS_STEP_INSTALL_SERVER_APP_WRITE_KEYS:
                step_t0 = tls13_profile_now_us();
                rc = tls13_install_server_application_write_keys(ctx);
                ctx->last_accept_timing.install_server_application_write_keys_us = tls13_profile_elapsed_us(step_t0);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    tls13_send_handshake_alert_for_error(ctx, rc);
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                ctx->server_handshake_step = ctx->request_client_auth ?
                    TLS13_SERVER_HS_STEP_RECV_CLIENT_CERTIFICATE :
                    TLS13_SERVER_HS_STEP_RECV_FINISHED;
                break;

            case TLS13_SERVER_HS_STEP_RECV_CLIENT_CERTIFICATE:
                step_t0 = tls13_profile_now_us();
                rc = tls13_recv_client_certificate(ctx);
                ctx->last_accept_timing.recv_client_certificate_us = tls13_profile_elapsed_us(step_t0);
                if(rc == NOXTLS_RETURN_TIMEOUT) {
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    tls13_send_handshake_alert_for_error(ctx, rc);
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                if(ctx->require_client_auth && (ctx->client_cert == NULL || ctx->client_cert_len == 0U)) {
                    rc = NOXTLS_RETURN_CERT_REQUIRED;
                    tls13_send_handshake_alert_for_error(ctx, rc);
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                ctx->server_handshake_step =
                    (ctx->client_cert != NULL && ctx->client_cert_len > 0U) ?
                        TLS13_SERVER_HS_STEP_RECV_CLIENT_CERTIFICATE_VERIFY :
                        TLS13_SERVER_HS_STEP_RECV_FINISHED;
                break;

            case TLS13_SERVER_HS_STEP_RECV_CLIENT_CERTIFICATE_VERIFY:
                step_t0 = tls13_profile_now_us();
                rc = tls13_recv_client_certificate_verify(ctx);
                ctx->last_accept_timing.recv_client_certificate_verify_us = tls13_profile_elapsed_us(step_t0);
                if(rc == NOXTLS_RETURN_TIMEOUT) {
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    if(ctx->base.base.state != TLS_STATE_CLOSED) {
                        tls13_send_handshake_alert_for_error(ctx, rc);
                    }
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                ctx->server_handshake_step = TLS13_SERVER_HS_STEP_RECV_FINISHED;
                break;

            case TLS13_SERVER_HS_STEP_RECV_FINISHED:
                step_t0 = tls13_profile_now_us();
                NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED);
                rc = noxtls_tls13_recv_finished_client(ctx);
                ctx->last_accept_timing.recv_finished_us = tls13_profile_elapsed_us(step_t0);
                if(rc == NOXTLS_RETURN_TIMEOUT) {
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED, rc);
                    if(ctx->base.base.state != TLS_STATE_CLOSED) {
                        tls13_send_handshake_alert_for_error(ctx, rc);
                    }
                    tls13_accept_log_fail(ctx, "recv_finished", rc);
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED, rc);
                ctx->server_handshake_step = tls13_is_dtls(ctx) ?
                    TLS13_SERVER_HS_STEP_FLUSH_ACK :
                    TLS13_SERVER_HS_STEP_INSTALL_CLIENT_APP_READ_KEYS;
                break;

            case TLS13_SERVER_HS_STEP_FLUSH_ACK:
                rc = tls13_dtls_flush_ack(ctx, 1U);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    tls13_send_handshake_alert_for_error(ctx, rc);
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                ctx->server_handshake_step = TLS13_SERVER_HS_STEP_INSTALL_CLIENT_APP_READ_KEYS;
                break;

            case TLS13_SERVER_HS_STEP_INSTALL_CLIENT_APP_READ_KEYS:
                step_t0 = tls13_profile_now_us();
                rc = tls13_install_client_application_read_keys(ctx);
                ctx->last_accept_timing.install_client_application_read_keys_us = tls13_profile_elapsed_us(step_t0);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    tls13_send_handshake_alert_for_error(ctx, rc);
                    ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                    return rc;
                }
                ctx->server_handshake_step = TLS13_SERVER_HS_STEP_SEND_NEW_SESSION_TICKET;
                break;

            case TLS13_SERVER_HS_STEP_SEND_NEW_SESSION_TICKET:
                if(!tls13_is_dtls(ctx)) {
                    step_t0 = tls13_profile_now_us();
                    rc = tls13_send_new_session_ticket(ctx);
                    ctx->last_accept_timing.send_new_session_ticket_us = tls13_profile_elapsed_us(step_t0);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        /* NST is optional post-handshake data; handshake is already complete. */
                        noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_accept: send_new_session_ticket failed rc=%d (ignored)\n", rc);
                    }
                } else {
                    ctx->last_accept_timing.send_new_session_ticket_us = 0U;
                }
                ctx->base.base.state = TLS_STATE_CONNECTED;
                ctx->server_handshake_step = TLS13_SERVER_HS_STEP_NONE;
                NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_CONNECTED);
#if NOXTLS_FEATURE_DTLS
                noxtls_dtls_mark_validated(&ctx->base);
#endif
                ctx->last_accept_timing.total_us = tls13_profile_elapsed_us(accept_t0);
                return NOXTLS_RETURN_SUCCESS;

            case TLS13_SERVER_HS_STEP_NONE:
            default:
                ctx->server_handshake_step = TLS13_SERVER_HS_STEP_RECV_CH;
                break;
        }
    }
}

/**
 * @brief Client: send 0-RTT early data when resuming, before the handshake completes.
 *
 * Encrypts with early traffic keys and sends as APPLICATION_DATA. Call only after ClientHello
 * and before EndOfEarlyData.
 *
 * @param[in,out] ctx  Resuming client context in early-data phase.
 * @param[in] data     Plaintext early application bytes.
 * @param[in] len      Length of @p data (must not exceed `TLS_MAX_RECORD_SIZE`).
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL`, `NOXTLS_RETURN_FAILED`, or
 *         `NOXTLS_RETURN_INVALID_PARAM` on invalid state or input.
 */
noxtls_return_t noxtls_tls13_send_early_data(tls13_context_t *ctx, const uint8_t *data, uint32_t len)
{
    uint32_t inner_len = TLS13_RECORD_WORKSPACE_HALF;
    uint32_t encrypted_len = TLS13_RECORD_WORKSPACE_HALF;
    uint8_t *inner;
    uint8_t *encrypted_record;
    noxtls_return_t rc;

    if(ctx == NULL || data == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_CLIENT || !ctx->early_data_phase || ctx->sent_end_of_early_data) {
        return NOXTLS_RETURN_FAILED;
    }
    if(len == 0 || len > TLS_MAX_RECORD_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->record_workspace == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    inner = ctx->record_workspace;
    encrypted_record = ctx->record_workspace + TLS13_RECORD_WORKSPACE_HALF;
    /* Optional: enforce max_early_data_size if server sent it (after EE we'd know; for now we allow) */

    rc = tls13_build_inner_plaintext(data, len, TLS_RECORD_APPLICATION_DATA, inner, &inner_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_tls13_encrypt_record_early(ctx, ctx->ticket_cipher_suite, TLS_RECORD_APPLICATION_DATA,
                                           inner, inner_len, encrypted_record, &encrypted_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_APPLICATION_DATA, encrypted_record, encrypted_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    ctx->early_data_sent = 1;
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
    uint32_t inner_len;
    uint32_t encrypted_len;  /* Extra space for tag */
    uint8_t *inner;
    uint8_t *encrypted_record;
    noxtls_return_t rc;
    uint32_t max_payload;

    if(ctx == NULL || data == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(ctx->base.base.state != TLS_STATE_CONNECTED) {
        return NOXTLS_RETURN_FAILED;
    }

    if(len > TLS_MAX_RECORD_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(ctx->record_workspace == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    inner = ctx->record_workspace;
    encrypted_record = ctx->record_workspace + TLS13_RECORD_WORKSPACE_HALF;
    max_payload = (ctx->record_size_limit_send > 0) ? ctx->record_size_limit_send : (uint32_t)TLS_MAX_RECORD_SIZE;

    /* RFC 8449: send in chunks not exceeding record_size_limit_send */
    uint32_t sent = 0;
    while(sent < len) {
        uint32_t chunk = len - sent;
        if(chunk > max_payload) {
            chunk = max_payload;
        }
        inner_len = TLS13_RECORD_WORKSPACE_HALF;
        rc = tls13_build_inner_plaintext(data + sent, chunk, TLS_RECORD_APPLICATION_DATA, inner, &inner_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }

        if(tls13_is_dtls(ctx)) {
            rc = noxtls_tls13_send_dtls13_encrypted_record(ctx, 0, TLS_RECORD_APPLICATION_DATA, inner, inner_len, 1);
        } else {
            encrypted_len = TLS13_RECORD_WORKSPACE_HALF;
            rc = noxtls_tls13_encrypt_record(ctx, TLS_RECORD_APPLICATION_DATA, inner, inner_len,
                                      encrypted_record, &encrypted_len);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_APPLICATION_DATA, encrypted_record, encrypted_len);
            }
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_send: chunk failed rc=%d sent=%u total=%u\n",
                                rc, chunk, sent);
            return rc;
        }
        sent += chunk;
    }
    noxtls_debug_printf("[TLS13_DEBUG] noxtls_tls13_send: sent total=%u\n", sent);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief DTLS 1.3: send RequestConnectionId post-handshake message (RFC 9147).
 * @param[in,out] ctx       Connected DTLS 1.3 context with peer CID negotiated.
 * @param[in] num_cids      Number of connection IDs requested from the peer.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL`, `NOXTLS_RETURN_FAILED`, or `NOXTLS_RETURN_TLS_ERROR`.
 */
noxtls_return_t noxtls_dtls13_send_request_connection_id(tls13_context_t *ctx, uint8_t num_cids)
{
    uint8_t msg[5];

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!tls13_is_dtls(ctx) || ctx->base.base.state != TLS_STATE_CONNECTED) {
        return NOXTLS_RETURN_FAILED;
    }
    if(ctx->peer_connection_id_len == 0U || ctx->cid_request_outstanding != 0U) {
        return NOXTLS_RETURN_TLS_ERROR;
    }

    msg[0] = TLS_HANDSHAKE_REQUEST_CONNECTION_ID;
    msg[1] = 0x00;
    msg[2] = 0x00;
    msg[3] = 0x01;
    msg[4] = num_cids;
    ctx->cid_request_outstanding = 1U;
    return tls13_send_encrypted_handshake(ctx, msg, sizeof(msg));
}

/**
 * @brief DTLS 1.3: send NewConnectionId with one connection ID (RFC 9147).
 * @param[in,out] ctx       Connected DTLS 1.3 context.
 * @param[in] cid           New connection ID bytes (may be NULL if @p cid_len is 0).
 * @param[in] cid_len       Length of @p cid (must match negotiated CID length when non-zero).
 * @param[in] usage         0 = replace active CID; 1 = add spare CID.
 * @return `NOXTLS_RETURN_SUCCESS` on success; error codes for invalid state, parameters, or send failure.
 */
noxtls_return_t noxtls_dtls13_send_new_connection_id(tls13_context_t *ctx, const uint8_t *cid, uint8_t cid_len, uint8_t usage)
{
    uint8_t msg[4U + 2U + 1U + 32U + 1U];
    uint32_t body_len;
    uint32_t offset = 0;
    noxtls_return_t rc;

    if(ctx == NULL || (cid == NULL && cid_len > 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    if(!tls13_is_dtls(ctx) || ctx->base.base.state != TLS_STATE_CONNECTED) {
        return NOXTLS_RETURN_FAILED;
    }
    if(usage > 1U || cid_len > 32U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->own_connection_id_len == 0U || cid_len != ctx->own_connection_id_len ||
       ctx->cid_new_outstanding != 0U) {
        return NOXTLS_RETURN_TLS_ERROR;
    }

    body_len = 2U + 1U + cid_len + 1U;
    msg[offset++] = TLS_HANDSHAKE_NEW_CONNECTION_ID;
    msg[offset++] = (uint8_t)((body_len >> 16) & 0xFF);
    msg[offset++] = (uint8_t)((body_len >> 8) & 0xFF);
    msg[offset++] = (uint8_t)(body_len & 0xFF);
    msg[offset++] = (uint8_t)(((1U + cid_len) >> 8) & 0xFF);
    msg[offset++] = (uint8_t)((1U + cid_len) & 0xFF);
    msg[offset++] = cid_len;
    memcpy(msg + offset, cid, cid_len);
    offset += cid_len;
    msg[offset++] = usage;
    rc = tls13_send_encrypted_handshake(ctx, msg, offset);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(usage == 0U) {
        memcpy(ctx->own_connection_id, cid, cid_len);
        ctx->own_connection_id_len = cid_len;
        tls13_dtls_own_cid_pool_clear(ctx);
    } else {
        rc = tls13_dtls_own_cid_pool_add(ctx, cid, cid_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    ctx->cid_new_outstanding = 1U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief DTLS 1.3: generate and send multiple NewConnectionId values (RFC 9147).
 * @param[in,out] ctx       Connected DTLS 1.3 context.
 * @param[in] num_cids      Number of CIDs to generate (capped by pool size).
 * @param[in] usage         0 = replace active CID; 1 = add spare CIDs.
 * @return `NOXTLS_RETURN_SUCCESS` on success; error codes for invalid state or crypto/send failure.
 */
noxtls_return_t noxtls_dtls13_send_new_connection_ids(tls13_context_t *ctx, uint8_t num_cids, uint8_t usage)
{
    uint8_t msg[4U + 2U + (DTLS13_MAX_CID_POOL * (1U + 32U)) + 1U];
    uint8_t generated[DTLS13_MAX_CID_POOL][32];
    uint8_t cid_len;
    uint8_t send_count;
    uint32_t vector_len;
    uint32_t body_len;
    uint32_t offset = 0;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!tls13_is_dtls(ctx) || ctx->base.base.state != TLS_STATE_CONNECTED) {
        return NOXTLS_RETURN_FAILED;
    }
    if(usage > 1U || ctx->own_connection_id_len == 0U || ctx->cid_new_outstanding != 0U ||
       (usage == 0U && num_cids == 0U)) {
        return NOXTLS_RETURN_TLS_ERROR;
    }

    cid_len = ctx->own_connection_id_len;
    send_count = num_cids;
    if(send_count > DTLS13_MAX_CID_POOL) {
        send_count = DTLS13_MAX_CID_POOL;
    }
    for(uint8_t i = 0U; i < send_count; i++) {
        rc = tls13_dtls_generate_cid(generated[i], cid_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    vector_len = (uint32_t)send_count * (1U + cid_len);
    body_len = 2U + vector_len + 1U;
    msg[offset++] = TLS_HANDSHAKE_NEW_CONNECTION_ID;
    msg[offset++] = (uint8_t)((body_len >> 16) & 0xFF);
    msg[offset++] = (uint8_t)((body_len >> 8) & 0xFF);
    msg[offset++] = (uint8_t)(body_len & 0xFF);
    msg[offset++] = (uint8_t)((vector_len >> 8) & 0xFF);
    msg[offset++] = (uint8_t)(vector_len & 0xFF);
    for(uint8_t i = 0U; i < send_count; i++) {
        msg[offset++] = cid_len;
        memcpy(msg + offset, generated[i], cid_len);
        offset += cid_len;
    }
    msg[offset++] = usage;

    rc = tls13_send_encrypted_handshake(ctx, msg, offset);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(usage == 0U && send_count > 0U) {
        memcpy(ctx->own_connection_id, generated[0], cid_len);
        ctx->own_connection_id_len = cid_len;
        tls13_dtls_own_cid_pool_clear(ctx);
        for(uint8_t i = 1U; i < send_count; i++) {
            (void)tls13_dtls_own_cid_pool_add(ctx, generated[i], cid_len);
        }
    } else {
        for(uint8_t i = 0U; i < send_count; i++) {
            rc = tls13_dtls_own_cid_pool_add(ctx, generated[i], cid_len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
        }
    }

    ctx->cid_new_outstanding = 1U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief DTLS 1.3: activate the next spare peer connection ID from the pool.
 * @param[in,out] ctx  Connected DTLS 1.3 context with spare CIDs available.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL`, `NOXTLS_RETURN_FAILED`, or `NOXTLS_RETURN_TIMEOUT`.
 */
noxtls_return_t noxtls_dtls13_rotate_connection_id(tls13_context_t *ctx)
{
    uint8_t cid_len;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!tls13_is_dtls(ctx) || ctx->base.base.state != TLS_STATE_CONNECTED) {
        return NOXTLS_RETURN_FAILED;
    }
    if(ctx->peer_spare_connection_id_count == 0U) {
        return NOXTLS_RETURN_TIMEOUT;
    }

    cid_len = ctx->peer_spare_connection_id_lens[0];
    memcpy(ctx->peer_connection_id, ctx->peer_spare_connection_ids[0], cid_len);
    ctx->peer_connection_id_len = cid_len;
    for(uint8_t i = 1U; i < ctx->peer_spare_connection_id_count; i++) {
        memcpy(ctx->peer_spare_connection_ids[i - 1U], ctx->peer_spare_connection_ids[i], 32U);
        ctx->peer_spare_connection_id_lens[i - 1U] = ctx->peer_spare_connection_id_lens[i];
    }
    ctx->peer_spare_connection_id_count--;
    memset(ctx->peer_spare_connection_ids[ctx->peer_spare_connection_id_count], 0, 32U);
    ctx->peer_spare_connection_id_lens[ctx->peer_spare_connection_id_count] = 0U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Send KeyUpdate and roll the local write traffic secret (RFC 8446 ?4.6.3).
 * @param[in,out] ctx              Established TLS 1.3 or DTLS 1.3 context.
 * @param[in] request_update       0 = update local keys only; 1 = request peer KeyUpdate.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL`, `NOXTLS_RETURN_FAILED`, or `NOXTLS_RETURN_INVALID_PARAM`.
 */
noxtls_return_t noxtls_tls13_send_key_update(tls13_context_t *ctx, uint8_t request_update)
{
    uint8_t msg[5];
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.state != TLS_STATE_CONNECTED) {
        return NOXTLS_RETURN_FAILED;
    }
    if(request_update > 1U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    msg[0] = TLS_HANDSHAKE_KEY_UPDATE;
    msg[1] = 0x00;
    msg[2] = 0x00;
    msg[3] = 0x01;
    msg[4] = request_update;

    rc = tls13_send_encrypted_handshake(ctx, msg, sizeof(msg));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return tls13_update_write_traffic_secret(ctx);
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
    uint32_t out_capacity;
    
    if(ctx == NULL || data == NULL || len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.state != TLS_STATE_CONNECTED) {
        return NOXTLS_RETURN_FAILED;
    }
    out_capacity = *len;
    if(out_capacity == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(ctx->pending_app_data != NULL && ctx->pending_app_data_len > 0) {
        uint32_t copy_len = ctx->pending_app_data_len;
        if(*len < copy_len) {
            copy_len = *len;
        }
        memcpy(data, ctx->pending_app_data, copy_len);
        *len = copy_len;
        free(ctx->pending_app_data);
        ctx->pending_app_data = NULL;
        ctx->pending_app_data_len = 0;
        return NOXTLS_RETURN_SUCCESS;
    }
    
    while(1) {
        uint32_t inner_plaintext_len = 0;
        rc = noxtls_tls_recv_record(&ctx->base.base, &record);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(record.length > 0 && record.data == NULL) {
            return NOXTLS_RETURN_FAILED;
        }

        if(record.type == TLS_RECORD_CHANGE_CIPHER_SPEC) {
            free(record.data);
            continue;
        }
        if(record.type == TLS_RECORD_ACK && tls13_is_dtls(ctx)) {
            if(record.length > 0U && record.data != NULL) {
                tls13_dtls_handle_ack(ctx, record.data, record.length);
            }
            free(record.data);
            continue;
        }
        if(record.type == TLS_RECORD_ALERT) {
            if(record.length < 2U) {
                free(record.data);
                tls13_send_fatal_alert(ctx, TLS_ALERT_UNEXPECTED_MESSAGE);
                ctx->peer_alert_received = 1;
                ctx->base.base.state = TLS_STATE_CLOSED;
                return NOXTLS_RETURN_FAILED;
            }
            free(record.data);
            ctx->peer_alert_received = 1;
            ctx->base.base.state = TLS_STATE_CLOSED;
            return NOXTLS_RETURN_FAILED;
        }
        if(tls13_is_dtls(ctx) && record.type >= 0x20U && record.type <= 0x3FU) {
            *len = out_capacity;
            rc = noxtls_tls13_decrypt_dtls13_record(ctx, record.data, record.length, &content_type, data, len);
            free(record.data);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_CRYPTO, NOXSIGHT_SEVERITY_ERROR,
                                NOXTLS_EVT_DECRYPT_FAIL, rc, record.length);
                if(rc == NOXTLS_RETURN_BAD_DATA) {
                    tls13_send_fatal_alert(ctx, TLS_ALERT_BAD_RECORD_MAC);
                } else {
                    tls13_send_handshake_alert_for_error(ctx, rc);
                }
                ctx->base.base.state = TLS_STATE_CLOSED;
                return rc;
            }
            noxtls_debug_printf("[TLS13_DEBUG] tls13_recv(app): dtls content_type=0x%02X plain_len=%u\n",
                                content_type,
                                (unsigned)*len);
        } else {
            if(record.type != TLS_RECORD_APPLICATION_DATA) {
                free(record.data);
                tls13_send_handshake_alert_for_error(ctx, NOXTLS_RETURN_TLS_ERROR);
                ctx->base.base.state = TLS_STATE_CLOSED;
                return NOXTLS_RETURN_TLS_ERROR;
            }

            /* Decrypt application data using AEAD */
            *len = out_capacity;
            rc = noxtls_tls13_decrypt_record(ctx, record.data, record.length, data, len);
            free(record.data);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_CRYPTO, NOXSIGHT_SEVERITY_ERROR,
                                NOXTLS_EVT_DECRYPT_FAIL, rc, record.length);
                if(rc == NOXTLS_RETURN_BAD_DATA) {
                    tls13_send_fatal_alert(ctx, TLS_ALERT_BAD_RECORD_MAC);
                } else {
                    tls13_send_handshake_alert_for_error(ctx, rc);
                }
                ctx->base.base.state = TLS_STATE_CLOSED;
                return rc;
            }
            inner_plaintext_len = *len;
            if(inner_plaintext_len > (uint32_t)(TLS_MAX_RECORD_SIZE + 1U)) {
                tls13_send_handshake_alert_for_error(ctx, NOXTLS_RETURN_RECORD_OVERFLOW);
                ctx->base.base.state = TLS_STATE_CLOSED;
                return NOXTLS_RETURN_RECORD_OVERFLOW;
            }

            rc = tls13_extract_inner_plaintext(data, len, &content_type);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                tls13_send_handshake_alert_for_error(ctx, NOXTLS_RETURN_TLS_ERROR);
                ctx->base.base.state = TLS_STATE_CLOSED;
                return NOXTLS_RETURN_TLS_ERROR;
            }
        }

        if((content_type == TLS_RECORD_HANDSHAKE || content_type == TLS_RECORD_ALERT) && *len == 0U) {
            tls13_send_fatal_alert(ctx, TLS_ALERT_UNEXPECTED_MESSAGE);
            ctx->base.base.state = TLS_STATE_CLOSED;
            return NOXTLS_RETURN_TLS_ERROR;
        }

        if(content_type == TLS_RECORD_APPLICATION_DATA) {
            /*
             * If a fragmented post-handshake handshake message is in progress,
             * receiving application data before completing it is unexpected.
             */
            if(ctx->handshake_buffer_len > ctx->handshake_buffer_pos) {
                tls13_send_handshake_alert_for_error(ctx, NOXTLS_RETURN_TLS_ERROR);
                ctx->base.base.state = TLS_STATE_CLOSED;
                return NOXTLS_RETURN_TLS_ERROR;
            }
            return NOXTLS_RETURN_SUCCESS;
        }

        if(content_type == TLS_RECORD_HANDSHAKE) {
            if(ctx->handshake_buffer_len == ctx->handshake_buffer_pos && *len >= 4U) {
                uint32_t first_hs_len = ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
                if(4U + first_hs_len < *len) {
                    /*
                     * Post-handshake records must carry a single complete handshake message.
                     * Fragmentation is handled via the handshake buffer path below.
                     * Reject only records that carry extra bytes beyond the first
                     * complete handshake message.
                     */
                    tls13_send_handshake_alert_for_error(ctx, NOXTLS_RETURN_TLS_ERROR);
                    ctx->base.base.state = TLS_STATE_CLOSED;
                    return NOXTLS_RETURN_TLS_ERROR;
                }
            }

            rc = tls13_handshake_buffer_append(ctx, data, *len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                tls13_send_handshake_alert_for_error(ctx, rc);
                ctx->base.base.state = TLS_STATE_CLOSED;
                return rc;
            }

            while(1) {
                uint8_t *hs_msg = NULL;
                uint32_t hs_msg_len = 0;
                rc = tls13_handshake_buffer_get(ctx, &hs_msg, &hs_msg_len);
                if(rc == NOXTLS_RETURN_FAILED) {
                    /* Need more handshake bytes across records. */
                    break;
                }
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    tls13_send_handshake_alert_for_error(ctx, rc);
                    ctx->base.base.state = TLS_STATE_CLOSED;
                    return rc;
                }

                rc = tls13_handle_post_handshake_message(ctx, hs_msg, hs_msg_len);
                free(hs_msg);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    tls13_send_handshake_alert_for_error(ctx, rc);
                    ctx->base.base.state = TLS_STATE_CLOSED;
                    return rc;
                }
            }
            continue;
        }
        if(content_type == TLS_RECORD_ALERT) {
            if(*len < 2U) {
                tls13_send_fatal_alert(ctx, TLS_ALERT_UNEXPECTED_MESSAGE);
                ctx->peer_alert_received = 1;
                ctx->base.base.state = TLS_STATE_CLOSED;
                return NOXTLS_RETURN_FAILED;
            }
            ctx->peer_alert_received = 1;
            ctx->base.base.state = TLS_STATE_CLOSED;
            return NOXTLS_RETURN_FAILED;
        }

        tls13_send_handshake_alert_for_error(ctx, NOXTLS_RETURN_TLS_ERROR);
        ctx->base.base.state = TLS_STATE_CLOSED;
        return NOXTLS_RETURN_TLS_ERROR;
    }
}

/**
 * @brief Send close_notify and mark the connection closed (TLS 1.3 / DTLS 1.3).
 * @param[in,out] ctx Established context.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p ctx is NULL; send error otherwise.
 */
noxtls_return_t noxtls_tls13_close(tls13_context_t *ctx)
{
    uint8_t alert[2];
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(ctx->base.base.state == TLS_STATE_CLOSED) {
        return NOXTLS_RETURN_SUCCESS;
    }

    alert[0] = TLS_ALERT_LEVEL_WARNING;
    alert[1] = TLS_ALERT_CLOSE_NOTIFY;

    if(ctx->handshake_encrypted && ctx->record_workspace != NULL && !tls13_is_dtls(ctx)) {
        uint32_t inner_len = (uint32_t)(TLS_MAX_RECORD_SIZE + 32);
        uint32_t encrypted_len = (uint32_t)(TLS_MAX_RECORD_SIZE + 32);
        uint8_t *inner = ctx->record_workspace;
        uint8_t *encrypted = ctx->record_workspace + (TLS_MAX_RECORD_SIZE + 32);

        rc = tls13_build_inner_plaintext(alert, sizeof(alert), TLS_RECORD_ALERT, inner, &inner_len);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_tls13_encrypt_record(ctx, TLS_RECORD_APPLICATION_DATA,
                                             inner, inner_len,
                                             encrypted, &encrypted_len);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                (void)noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_APPLICATION_DATA,
                                             encrypted, encrypted_len);
            } else {
                (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_WARNING, TLS_ALERT_CLOSE_NOTIFY);
            }
        } else {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_WARNING, TLS_ALERT_CLOSE_NOTIFY);
        }
    } else {
        (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_WARNING, TLS_ALERT_CLOSE_NOTIFY);
    }
    
    ctx->base.base.state = TLS_STATE_CLOSED;
    
    return NOXTLS_RETURN_SUCCESS;
}
