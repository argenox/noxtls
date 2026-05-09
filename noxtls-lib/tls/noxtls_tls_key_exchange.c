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
* File:    noxtls_tls_key_exchange.c
* Summary: TLS Key Exchange Implementation (ECDHE, etc.)
*
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_tls_key_exchange.h"
#include "noxtls_tls_common.h"
#include "noxtls_tls12.h"
#include "noxtls_tls13.h"
#include "pkc/ecdh/noxtls_ecdh.h"
#include "pkc/x25519/noxtls_x25519.h"
#include "pkc/rsa/noxtls_rsa.h"
#include "pkc/dh/noxtls_dh.h"
#include "certs/noxtls_x509.h"
#include "mdigest/noxtls_hash.h"

#define DHE_TO_SIGN_SIZE  (32u + 32u + 1536u)
#define DHE_SIG_BUF_SIZE  512u

/**
 * @brief Map TLS named group to ECC curve type
 */
noxtls_return_t tls_named_group_to_ecc_curve(uint16_t named_group, ecc_curve_t *curve_type)
{
    if(curve_type == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    switch(named_group) {
        case TLS_NAMED_GROUP_SECP256R1:
            *curve_type = ECC_SECP256R1;
            return NOXTLS_RETURN_SUCCESS;
            
        case TLS_NAMED_GROUP_SECP384R1:
            *curve_type = ECC_SECP384R1;
            return NOXTLS_RETURN_SUCCESS;
            
        case TLS_NAMED_GROUP_SECP521R1:
            *curve_type = ECC_SECP521R1;
            return NOXTLS_RETURN_SUCCESS;
            
        case TLS_NAMED_GROUP_X25519:
            *curve_type = ECC_SECP256R1;  /* unused for X25519; callers branch on named_group */
            return NOXTLS_RETURN_SUCCESS;
        case TLS_NAMED_GROUP_X448:
            /* X448 not yet supported */
            return NOXTLS_RETURN_FAILED;
            
        default:
            return NOXTLS_RETURN_FAILED;
    }
}

/**
 * @brief Map ECC curve type to TLS named group
 */
noxtls_return_t tls_ecc_curve_to_named_group(ecc_curve_t curve_type, uint16_t *named_group)
{
    if(named_group == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    switch(curve_type) {
        case ECC_SECP256R1:
            *named_group = TLS_NAMED_GROUP_SECP256R1;
            return NOXTLS_RETURN_SUCCESS;
            
        case ECC_SECP384R1:
            *named_group = TLS_NAMED_GROUP_SECP384R1;
            return NOXTLS_RETURN_SUCCESS;
            
        case ECC_SECP521R1:
            *named_group = TLS_NAMED_GROUP_SECP521R1;
            return NOXTLS_RETURN_SUCCESS;
            
        default:
            return NOXTLS_RETURN_FAILED;
    }
}

/**
 * @brief Encode ECC point in uncompressed format for TLS
 * 
 * Format: 0x04 || x-coordinate || y-coordinate
 * 
 * @param point ECC point to encode
 * @param output Output buffer
 * @param output_len Input: buffer size, Output: encoded length
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t tls_encode_ecc_point_uncompressed(const ecc_point_t *point, uint8_t *output, uint32_t *output_len)
{
    if(point == NULL || output == NULL || output_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    uint32_t required_len = 1 + (2 * point->size);  /* 0x04 + x + y */
    
    if(*output_len < required_len) {
        *output_len = required_len;
        return NOXTLS_RETURN_FAILED;
    }
    
    uint32_t offset = 0;
    
    /* Uncompressed point format indicator */
    output[offset++] = 0x04;
    
    /* X-coordinate (big-endian) */
    memcpy(output + offset, point->x, point->size);
    offset += point->size;
    
    /* Y-coordinate (big-endian) */
    memcpy(output + offset, point->y, point->size);
    offset += point->size;
    
    *output_len = offset;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Decode ECC point from uncompressed format for TLS
 * 
 * Format: 0x04 || x-coordinate || y-coordinate
 * 
 * @param encoded Encoded point data
 * @param encoded_len Length of encoded data
 * @param point Output ECC point
 * @param curve_type Curve type to use
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t tls_decode_ecc_point_uncompressed(const uint8_t *encoded, uint32_t encoded_len, ecc_point_t *point, ecc_curve_t curve_type)
{
    uint32_t expected_size;
    
    if(encoded == NULL || point == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Determine expected point size based on curve */
    switch(curve_type) {
        case ECC_SECP256R1:
            expected_size = 32;
            break;
        case ECC_SECP384R1:
            expected_size = 48;
            break;
        case ECC_SECP521R1:
            expected_size = 66;  /* (521+7)/8 = 66 */
            break;
        default:
            return NOXTLS_RETURN_FAILED;
    }
    
    uint32_t required_len = 1 + (2 * expected_size);  /* 0x04 + x + y */
    
    if(encoded_len < required_len) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Check uncompressed format indicator */
    if(encoded[0] != TLS_EC_POINT_UNCOMPRESSED) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Initialize point */
    noxtls_ecc_point_init(point, expected_size);
    point->size = expected_size;
    
    /* Decode x-coordinate */
    memcpy(point->x, encoded + 1, expected_size);
    
    /* Decode y-coordinate */
    memcpy(point->y, encoded + 1 + expected_size, expected_size);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize ECDHE context
 */
noxtls_return_t tls_ecdhe_context_init(tls_ecdhe_context_t *ctx, uint16_t named_group)
{
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    memset(ctx, 0, sizeof(tls_ecdhe_context_t));
    ctx->named_group = named_group;
    
    if(named_group == TLS_NAMED_GROUP_X25519) {
        /* X25519: no ECC key; curve_type unused */
        return NOXTLS_RETURN_SUCCESS;
    }
    
    /* Map named group to curve type */
    rc = tls_named_group_to_ecc_curve(named_group, &ctx->curve_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    /* Initialize ephemeral key */
    rc = noxtls_ecc_key_init(&ctx->ephemeral_key, ctx->curve_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Free ECDHE context
 */
noxtls_return_t tls_ecdhe_context_free(tls_ecdhe_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->named_group != TLS_NAMED_GROUP_X25519) {
        noxtls_ecc_key_free(&ctx->ephemeral_key);
    } else {
        memset(ctx->x25519_private_key, 0, sizeof(ctx->x25519_private_key));
        memset(ctx->x25519_public_key, 0, sizeof(ctx->x25519_public_key));
    }
    
    /* Free premaster secret (TLS 1.2) */
    if(ctx->premaster_secret) {
        memset(ctx->premaster_secret, 0, ctx->premaster_secret_len);
        free(ctx->premaster_secret);
        ctx->premaster_secret = NULL;
        ctx->premaster_secret_len = 0;
    }
    
    /* Free shared secret (TLS 1.3) */
    if(ctx->shared_secret) {
        memset(ctx->shared_secret, 0, ctx->shared_secret_len);
        free(ctx->shared_secret);
        ctx->shared_secret = NULL;
        ctx->shared_secret_len = 0;
    }
    
    memset(ctx, 0, sizeof(tls_ecdhe_context_t));
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generate ephemeral key pair for ECDHE
 */
noxtls_return_t tls_ecdhe_generate_ephemeral_key(tls_ecdhe_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->named_group == TLS_NAMED_GROUP_X25519) {
        return noxtls_x25519_generate_key(ctx->x25519_private_key, ctx->x25519_public_key);
    }
    
    if(ctx->ephemeral_key.curve == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Generate ephemeral key pair */
    return noxtls_ecc_key_generate(&ctx->ephemeral_key, ctx->curve_type);
}

/**
 * @brief Compute shared secret from peer's public key
 */
noxtls_return_t tls_ecdhe_compute_shared_secret(tls_ecdhe_context_t *ctx, const ecc_point_t *peer_public_key)
{
    noxtls_return_t rc;
    uint8_t *secret_buffer = NULL;
    uint32_t secret_len;
    
    if(ctx == NULL || peer_public_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->ephemeral_key.curve == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    secret_len = ctx->ephemeral_key.curve->size;
    secret_buffer = (uint8_t*)malloc(secret_len);
    if(secret_buffer == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Compute shared secret using ECDH */
    rc = noxtls_ecdh_compute_shared_secret(&ctx->ephemeral_key, (ecc_point_t*)peer_public_key, secret_buffer, &secret_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(secret_buffer);
        return rc;
    }
    
    /* Store shared secret (for TLS 1.3) */
    if(ctx->shared_secret) {
        memset(ctx->shared_secret, 0, ctx->shared_secret_len);
        free(ctx->shared_secret);
    }
    
    ctx->shared_secret = secret_buffer;
    ctx->shared_secret_len = secret_len;

    noxtls_debug_printf("[TLS12_DEBUG] ecdhe shared_secret_len=%u shared[0..3]=%02X%02X%02X%02X\n",
                          ctx->shared_secret_len,
                          ctx->shared_secret_len > 0 ? ctx->shared_secret[0] : 0,
                          ctx->shared_secret_len > 1 ? ctx->shared_secret[1] : 0,
                          ctx->shared_secret_len > 2 ? ctx->shared_secret[2] : 0,
                          ctx->shared_secret_len > 3 ? ctx->shared_secret[3] : 0);
    fflush(stdout);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Get encoded public key for transmission
 */
noxtls_return_t tls_ecdhe_get_public_key_encoded(tls_ecdhe_context_t *ctx, uint8_t *output, uint32_t *output_len)
{
    if(ctx == NULL || output == NULL || output_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->named_group == TLS_NAMED_GROUP_X25519) {
        if(*output_len < NOXTLS_X25519_KEY_SIZE) {
            *output_len = NOXTLS_X25519_KEY_SIZE;
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(output, ctx->x25519_public_key, NOXTLS_X25519_KEY_SIZE);
        *output_len = NOXTLS_X25519_KEY_SIZE;
        return NOXTLS_RETURN_SUCCESS;
    }
    
    if(ctx->ephemeral_key.curve == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    return tls_encode_ecc_point_uncompressed(&ctx->ephemeral_key.Q, output, output_len);
}

/**
 * @brief Compute shared secret from peer's X25519 public key (32 bytes)
 */
noxtls_return_t tls_ecdhe_compute_shared_secret_x25519(tls_ecdhe_context_t *ctx, const uint8_t peer_public_key[32])
{
    uint8_t *secret_buffer;
    noxtls_return_t rc;
    
    if(ctx == NULL || peer_public_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->named_group != TLS_NAMED_GROUP_X25519) {
        return NOXTLS_RETURN_FAILED;
    }
    
    secret_buffer = (uint8_t*)malloc(NOXTLS_X25519_KEY_SIZE);
    if(secret_buffer == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    rc = noxtls_x25519_shared_secret(ctx->x25519_private_key, peer_public_key, secret_buffer);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(secret_buffer);
        return rc;
    }
    
    if(ctx->shared_secret) {
        memset(ctx->shared_secret, 0, ctx->shared_secret_len);
        free(ctx->shared_secret);
    }
    
    ctx->shared_secret = secret_buffer;
    ctx->shared_secret_len = NOXTLS_X25519_KEY_SIZE;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2: Send Server Key Exchange (ECDHE)
 * 
 * Format:
 * - Curve type (1 byte) = 0x03 (named_curve)
 * - Named curve (2 bytes)
 * - Public key length (1 byte)
 * - Public key (uncompressed format)
 * - Signature algorithm (2 bytes)
 * - Signature length (2 bytes)
 * - Signature (when server_private_rsa is set)
 */
noxtls_return_t tls12_ecdhe_send_server_key_exchange(tls12_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx)
{
    if(ctx == NULL || ecdhe_ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    /* workspace layout: server_key_exchange 0..1023, to_sign 1024..1343, sig_buf 1344..1855 */
    uint8_t *server_key_exchange = ctx->handshake_workspace;
    uint8_t *to_sign = (ctx->handshake_workspace != NULL) ? (ctx->handshake_workspace + 1024) : NULL;
    uint8_t *sig_buf = (ctx->handshake_workspace != NULL) ? (ctx->handshake_workspace + 1344) : NULL;
    if(server_key_exchange == NULL) {
        server_key_exchange = (uint8_t*)noxtls_malloc(1024 + 320 + 512);
        if(server_key_exchange == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        to_sign = server_key_exchange + 1024;
        sig_buf = server_key_exchange + 1344;
    }
    uint32_t offset = 0;
    uint8_t public_key_encoded[133];  /* Max: 1 + 2*66 for P-521 */
    uint32_t public_key_len = sizeof(public_key_encoded);
    noxtls_return_t rc;
    uint32_t params_start;  /* offset of curve_type (after handshake header) */
    uint32_t params_len;
    uint32_t to_sign_len;
    uint32_t sig_len;

    /* Build Server Key Exchange message */
    server_key_exchange[offset++] = TLS_HANDSHAKE_SERVER_KEY_EXCHANGE;
    server_key_exchange[offset++] = 0x00;  /* Length (3 bytes) - placeholder */
    server_key_exchange[offset++] = 0x00;
    server_key_exchange[offset++] = 0x00;

    params_start = offset;
    /* Curve type: named_curve (0x03) */
    server_key_exchange[offset++] = TLS_EC_CURVE_TYPE_NAMED;
    server_key_exchange[offset++] = (ecdhe_ctx->named_group >> 8) & 0xFF;
    server_key_exchange[offset++] = ecdhe_ctx->named_group & 0xFF;
    memset(public_key_encoded, 0, sizeof(public_key_encoded));
    rc = tls_ecdhe_get_public_key_encoded(ecdhe_ctx, public_key_encoded, &public_key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        if(server_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_key_exchange, 1024 + 320 + 512); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return rc;
    }
    server_key_exchange[offset++] = public_key_len & 0xFF;
    memcpy(server_key_exchange + offset, public_key_encoded, public_key_len);
    offset += public_key_len;
    params_len = offset - params_start;

    if(ctx->crypto_provider && ctx->crypto_provider->ops && ctx->crypto_provider->ops->rsa_sign && ctx->server_private_key_handle) {
        if(320u < (uint32_t)(TLS_RANDOM_SIZE + TLS_RANDOM_SIZE + params_len)) {
            if(server_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_key_exchange, 1024 + 320 + 512); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(to_sign, ctx->client_random, TLS_RANDOM_SIZE);
        memcpy(to_sign + TLS_RANDOM_SIZE, ctx->server_random, TLS_RANDOM_SIZE);
        memcpy(to_sign + TLS_RANDOM_SIZE * 2, server_key_exchange + params_start, params_len);
        to_sign_len = TLS_RANDOM_SIZE + TLS_RANDOM_SIZE + params_len;
        sig_len = 512;
        rc = ctx->crypto_provider->ops->rsa_sign(ctx->crypto_provider->ctx, ctx->server_private_key_handle,
                to_sign, to_sign_len, sig_buf, &sig_len, (noxtls_crypto_hash_algo_t)NOXTLS_HASH_SHA_256);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(server_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_key_exchange, 1024 + 320 + 512); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return rc;
        }
        server_key_exchange[offset++] = TLS_EC_POINT_UNCOMPRESSED;
        server_key_exchange[offset++] = 0x01;
        server_key_exchange[offset++] = (sig_len >> 8) & 0xFF;
        server_key_exchange[offset++] = sig_len & 0xFF;
        if(offset + sig_len > TLS_CLIENT_HELLO_BASE_SIZE) {
            if(server_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_key_exchange, 1024 + 320 + 512); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(server_key_exchange + offset, sig_buf, sig_len);
        offset += sig_len;
    } else if(ctx->server_private_rsa != NULL) {
        /* TLS 1.2: sign Hash(client_random + server_random + params); use RSA PKCS#1 with SHA256 */
        if(320u < (uint32_t)(TLS_RANDOM_SIZE + TLS_RANDOM_SIZE + params_len)) {
            if(server_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_key_exchange, 1024 + 320 + 512); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(to_sign, ctx->client_random, TLS_RANDOM_SIZE);
        memcpy(to_sign + TLS_RANDOM_SIZE, ctx->server_random, TLS_RANDOM_SIZE);
        memcpy(to_sign + TLS_RANDOM_SIZE * 2, server_key_exchange + params_start, params_len);
        to_sign_len = TLS_RANDOM_SIZE + TLS_RANDOM_SIZE + params_len;
        sig_len = 512;
        rc = noxtls_rsa_sign((const rsa_key_t *)ctx->server_private_rsa, to_sign, to_sign_len,
                             sig_buf, &sig_len, NOXTLS_HASH_SHA_256);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(server_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_key_exchange, 1024 + 320 + 512); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return rc;
        }
        /* Signature algorithm: sha256(4) + rsa(1) = 0x0401 */
        server_key_exchange[offset++] = TLS_EC_POINT_UNCOMPRESSED;
        server_key_exchange[offset++] = 0x01;
        server_key_exchange[offset++] = (sig_len >> 8) & 0xFF;
        server_key_exchange[offset++] = sig_len & 0xFF;
        if(offset + sig_len > TLS_CLIENT_HELLO_BASE_SIZE) {
            if(server_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_key_exchange, 1024 + 320 + 512); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(server_key_exchange + offset, sig_buf, sig_len);
        offset += sig_len;
    } else {
        server_key_exchange[offset++] = 0x00;
        server_key_exchange[offset++] = 0x00;
        server_key_exchange[offset++] = 0x00;
        server_key_exchange[offset++] = 0x00;
    }

    uint32_t handshake_len = offset - 4;
    server_key_exchange[1] = (handshake_len >> 16) & 0xFF;
    server_key_exchange[2] = (handshake_len >> 8) & 0xFF;
    server_key_exchange[3] = handshake_len & 0xFF;
    rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, server_key_exchange, offset);
    if(server_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_key_exchange, 1024 + 320 + 512); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return rc;
}

/**
 * @brief TLS 1.2: Receive Server Key Exchange (ECDHE)
 */
noxtls_return_t tls12_ecdhe_recv_server_key_exchange(tls12_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    uint32_t offset;
    uint8_t curve_type;
    uint16_t named_curve;
    uint8_t public_key_len;
    ecc_point_t peer_public_key;
    
    if(ctx == NULL || ecdhe_ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_CLIENT) {
        return NOXTLS_RETURN_FAILED;
    }
    
    rc = noxtls_tls_recv_record(&ctx->base.base, &record);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(record.length > 0 && record.data == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if(record.type != TLS_RECORD_HANDSHAKE) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    if(record.data[0] != TLS_HANDSHAKE_SERVER_KEY_EXCHANGE) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    offset = 4;  /* Skip handshake header */
    
    /* Curve type */
    if(offset >= record.length) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    curve_type = record.data[offset++];
    
    if(curve_type != TLS_EC_CURVE_TYPE_NAMED) {  /* Must be named_curve */
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Named curve */
    if(offset + 2 > record.length) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    named_curve = (record.data[offset] << 8) | record.data[offset + 1];
    offset += 2;
    
    /* Verify named curve matches */
    if(named_curve != ecdhe_ctx->named_group) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Public key length */
    if(offset >= record.length) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    public_key_len = record.data[offset++];
    
    /* Public key */
    if(offset + public_key_len > record.length) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    if(ecdhe_ctx->named_group == TLS_NAMED_GROUP_X25519) {
        if(public_key_len != NOXTLS_X25519_KEY_SIZE) {
            free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        rc = tls_ecdhe_compute_shared_secret_x25519(ecdhe_ctx, record.data + offset);
        free(record.data);
        return rc;
    }
    
    /* Decode peer's public key */
    rc = tls_decode_ecc_point_uncompressed(record.data + offset, public_key_len, &peer_public_key, ecdhe_ctx->curve_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(record.data);
        return rc;
    }
    offset += public_key_len;
    uint32_t params_end = offset;  /* params = record.data[4..params_end-1] */

    /* Signature algorithm (2 bytes) and signature length (2 bytes) */
    if(offset + 4 > record.length) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    (void)record.data[offset];
    (void)record.data[offset + 1];
    uint16_t sig_len = (uint16_t)((record.data[offset + 2] << 8) | record.data[offset + 3]);
    offset += 4;
    if(offset + sig_len > record.length) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    if(sig_len > 0) {
        if(ctx->server_cert_parsed == NULL) {
            free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        {
            x509_certificate_t *cert = (x509_certificate_t *)ctx->server_cert_parsed;
            if(cert->rsa_modulus == NULL || cert->rsa_exponent == NULL) {
                free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            uint32_t key_bytes = cert->rsa_modulus_len;
            rsa_key_size_t key_size = (key_bytes == 128) ? RSA_1024_BIT : (key_bytes == 256) ? RSA_2048_BIT :
                                      (key_bytes == 384) ? RSA_3072_BIT : (key_bytes == 512) ? RSA_4096_BIT : (rsa_key_size_t)0;
            if(key_bytes != 128 && key_bytes != 256 && key_bytes != 384 && key_bytes != 512) {
                free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            rsa_key_t rsa_key;
            rc = noxtls_rsa_key_init(&rsa_key, key_size);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                free(record.data);
                return rc;
            }
            memcpy(rsa_key.n, cert->rsa_modulus, cert->rsa_modulus_len);
            memcpy(rsa_key.e, cert->rsa_exponent, cert->rsa_exponent_len);
            uint32_t params_len = params_end - 4;  /* curve_type through public key */
            if(params_len > 256u) {
                noxtls_rsa_key_free(&rsa_key);
                free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            uint8_t *to_verify = (ctx->handshake_workspace != NULL) ? ctx->handshake_workspace : (uint8_t*)noxtls_malloc(320);
            if(to_verify == NULL) {
                noxtls_rsa_key_free(&rsa_key);
                free(record.data);
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            memcpy(to_verify, ctx->client_random, TLS_RANDOM_SIZE);
            memcpy(to_verify + TLS_RANDOM_SIZE, ctx->server_random, TLS_RANDOM_SIZE);
            memcpy(to_verify + TLS_RANDOM_SIZE * 2, record.data + 4, params_len);
            rc = noxtls_rsa_verify(&rsa_key, to_verify, (uint32_t)(TLS_RANDOM_SIZE + TLS_RANDOM_SIZE + params_len),
                                  record.data + offset, sig_len, NOXTLS_HASH_SHA_256);
            noxtls_rsa_key_free(&rsa_key);
            if(to_verify != ctx->handshake_workspace) NOXTLS_SECURE_FREE(to_verify, 320); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
        }
        offset += sig_len;
    }

    /* Compute shared secret */
    rc = tls_ecdhe_compute_shared_secret(ecdhe_ctx, &peer_public_key);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(record.data);
        return rc;
    }
    
    free(record.data);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2: Send Client Key Exchange (ECDHE)
 * 
 * Format:
 * - Public key length (1 byte)
 * - Public key (uncompressed format)
 */
noxtls_return_t tls12_ecdhe_send_client_key_exchange(tls12_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx)
{
    if(ctx == NULL || ecdhe_ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_CLIENT) {
        return NOXTLS_RETURN_FAILED;
    }
    uint8_t *client_key_exchange = ctx->handshake_workspace;
    if(client_key_exchange == NULL) {
        client_key_exchange = (uint8_t*)noxtls_malloc(512);
        if(client_key_exchange == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    uint32_t offset = 0;
    uint8_t public_key_encoded[133];  /* Max: 1 + 2*66 for P-521 */
    uint32_t public_key_len = sizeof(public_key_encoded);
    noxtls_return_t rc;
    
    /* Build Client Key Exchange message */
    client_key_exchange[offset++] = TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE;
    client_key_exchange[offset++] = 0x00;  /* Length (3 bytes) - placeholder */
    client_key_exchange[offset++] = 0x00;
    client_key_exchange[offset++] = 0x00;
    
    /* Get encoded public key */
    rc = tls_ecdhe_get_public_key_encoded(ecdhe_ctx, public_key_encoded, &public_key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, 1024); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return rc;
    }
    
    /* Public key length */
    client_key_exchange[offset++] = public_key_len & 0xFF;
    
    /* Public key */
    memcpy(client_key_exchange + offset, public_key_encoded, public_key_len);
    offset += public_key_len;
    
    /* Update handshake message length */
    uint32_t handshake_len = offset - 4;
    client_key_exchange[1] = (handshake_len >> 16) & 0xFF;
    client_key_exchange[2] = (handshake_len >> 8) & 0xFF;
    client_key_exchange[3] = handshake_len & 0xFF;
    
    /* Send via record layer */
    rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, client_key_exchange, offset);
    if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, 1024); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return rc;
}

/**
 * @brief TLS 1.2: Receive Client Key Exchange (ECDHE)
 */
noxtls_return_t tls12_ecdhe_recv_client_key_exchange(tls12_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    uint32_t offset;
    uint8_t public_key_len;
    ecc_point_t peer_public_key;
    
    if(ctx == NULL || ecdhe_ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    rc = noxtls_tls_recv_record(&ctx->base.base, &record);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(record.length > 0 && record.data == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if(record.type != TLS_RECORD_HANDSHAKE) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    if(record.data[0] != TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    offset = 4;  /* Skip handshake header */
    
    /* Public key length */
    if(offset >= record.length) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    public_key_len = record.data[offset++];
    
    /* Public key */
    if(offset + public_key_len > record.length) {
        free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    if(ecdhe_ctx->named_group == TLS_NAMED_GROUP_X25519) {
        if(public_key_len != NOXTLS_X25519_KEY_SIZE) {
            free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        rc = tls_ecdhe_compute_shared_secret_x25519(ecdhe_ctx, record.data + offset);
        free(record.data);
        return rc;
    }
    
    /* Decode peer's public key */
    rc = tls_decode_ecc_point_uncompressed(record.data + offset, public_key_len, &peer_public_key, ecdhe_ctx->curve_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(record.data);
        return rc;
    }
    
    /* Compute shared secret */
    rc = tls_ecdhe_compute_shared_secret(ecdhe_ctx, &peer_public_key);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(record.data);
        return rc;
    }
    
    free(record.data);
    
    return NOXTLS_RETURN_SUCCESS;
}

/* ========== TLS 1.2 DHE (FFDHE) ========== */

noxtls_return_t tls_dhe_context_init(tls_dhe_context_t *ctx, uint16_t named_group)
{
    const uint8_t *p = NULL;
    const uint8_t *g = NULL;
    uint32_t p_len = 0;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    memset(ctx, 0, sizeof(tls_dhe_context_t));
    if(noxtls_dh_ffdhe_params(named_group, &p, &g, &p_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    ctx->named_group = named_group;
    ctx->p_len = p_len;
    ctx->server_private = (uint8_t*)malloc(p_len);
    ctx->server_public  = (uint8_t*)malloc(p_len);
    ctx->client_private = (uint8_t*)malloc(p_len);
    ctx->client_public  = (uint8_t*)malloc(p_len);
    if(ctx->server_private == NULL || ctx->server_public == NULL ||
       ctx->client_private == NULL || ctx->client_public == NULL) {
        if(ctx->server_private) free(ctx->server_private);
        if(ctx->server_public)  free(ctx->server_public);
        if(ctx->client_private) free(ctx->client_private);
        if(ctx->client_public)  free(ctx->client_public);
        memset(ctx, 0, sizeof(tls_dhe_context_t));
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t tls_dhe_context_free(tls_dhe_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->server_private) { free(ctx->server_private); ctx->server_private = NULL; }
    if(ctx->server_public)  { free(ctx->server_public);  ctx->server_public = NULL; }
    if(ctx->client_private) { free(ctx->client_private); ctx->client_private = NULL; }
    if(ctx->client_public)  { free(ctx->client_public);  ctx->client_public = NULL; }
    ctx->p_len = 0;
    ctx->premaster_secret_len = 0;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t tls12_dhe_send_server_key_exchange(tls12_context_t *ctx, tls_dhe_context_t *dhe_ctx, uint8_t *msg_out, uint32_t msg_out_size, uint32_t *msg_out_len)
{
    const uint8_t *p = NULL;
    const uint8_t *g = NULL;
    uint32_t p_len = 0;
    uint8_t *server_key_exchange;
    uint8_t *to_sign;
    uint8_t *sig_buf;
    uint8_t *alloc_aux = NULL;  /* when workspace used: to_sign+sig_buf block */
    uint32_t offset = 0;
    uint32_t params_start;
    uint32_t params_len;
    uint32_t to_sign_len;
    uint32_t sig_len;
    noxtls_return_t rc;

    if(ctx == NULL || dhe_ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_dh_ffdhe_params(dhe_ctx->named_group, &p, &g, &p_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(p_len != dhe_ctx->p_len) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = noxtls_dh_generate_key(p, p_len, g, p_len, dhe_ctx->server_private, dhe_ctx->server_public);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(ctx->handshake_workspace != NULL) {
        server_key_exchange = ctx->handshake_workspace;
        alloc_aux = (uint8_t*)noxtls_malloc(DHE_TO_SIGN_SIZE + DHE_SIG_BUF_SIZE);
        if(alloc_aux == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        to_sign = alloc_aux;
        sig_buf = alloc_aux + DHE_TO_SIGN_SIZE;
    } else {
        server_key_exchange = (uint8_t*)noxtls_malloc(2048 + DHE_TO_SIGN_SIZE + DHE_SIG_BUF_SIZE);
        if(server_key_exchange == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        to_sign = server_key_exchange + 2048;
        sig_buf = server_key_exchange + 2048 + DHE_TO_SIGN_SIZE;
    }

    server_key_exchange[offset++] = TLS_HANDSHAKE_SERVER_KEY_EXCHANGE;
    server_key_exchange[offset++] = 0x00;
    server_key_exchange[offset++] = 0x00;
    server_key_exchange[offset++] = 0x00;
    params_start = offset;

    /* dh_p: 2-byte length + p */
    server_key_exchange[offset++] = (p_len >> 8) & 0xFF;
    server_key_exchange[offset++] = p_len & 0xFF;
    memcpy(server_key_exchange + offset, p, p_len);
    offset += p_len;
    /* dh_g: 2-byte length + g */
    server_key_exchange[offset++] = (p_len >> 8) & 0xFF;
    server_key_exchange[offset++] = p_len & 0xFF;
    memcpy(server_key_exchange + offset, g, p_len);
    offset += p_len;
    /* dh_Ys: 2-byte length + Ys */
    server_key_exchange[offset++] = (p_len >> 8) & 0xFF;
    server_key_exchange[offset++] = p_len & 0xFF;
    memcpy(server_key_exchange + offset, dhe_ctx->server_public, p_len);
    offset += p_len;
    params_len = offset - params_start;

    if(ctx->crypto_provider && ctx->crypto_provider->ops && ctx->crypto_provider->ops->rsa_sign && ctx->server_private_key_handle && params_len <= DHE_TO_SIGN_SIZE - (TLS_RANDOM_SIZE * 2u)) {
        memcpy(to_sign, ctx->client_random, TLS_RANDOM_SIZE);
        memcpy(to_sign + TLS_RANDOM_SIZE, ctx->server_random, TLS_RANDOM_SIZE);
        memcpy(to_sign + TLS_RANDOM_SIZE * 2, server_key_exchange + params_start, params_len);
        to_sign_len = TLS_RANDOM_SIZE + TLS_RANDOM_SIZE + params_len;
        sig_len = DHE_SIG_BUF_SIZE;
        rc = ctx->crypto_provider->ops->rsa_sign(ctx->crypto_provider->ctx, ctx->server_private_key_handle,
                to_sign, to_sign_len, sig_buf, &sig_len, (noxtls_crypto_hash_algo_t)NOXTLS_HASH_SHA_256);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(alloc_aux) NOXTLS_SECURE_FREE(alloc_aux, DHE_TO_SIGN_SIZE + DHE_SIG_BUF_SIZE);
            if(server_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_key_exchange, 1024 + 320 + 512); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return rc;
        }
        server_key_exchange[offset++] = TLS_EC_POINT_UNCOMPRESSED;
        server_key_exchange[offset++] = 0x01;
        server_key_exchange[offset++] = (sig_len >> 8) & 0xFF;
        server_key_exchange[offset++] = sig_len & 0xFF;
        memcpy(server_key_exchange + offset, sig_buf, sig_len);
        offset += sig_len;
    } else if(ctx->server_private_rsa != NULL && params_len <= DHE_TO_SIGN_SIZE - (TLS_RANDOM_SIZE * 2u)) {
        memcpy(to_sign, ctx->client_random, TLS_RANDOM_SIZE);
        memcpy(to_sign + TLS_RANDOM_SIZE, ctx->server_random, TLS_RANDOM_SIZE);
        memcpy(to_sign + TLS_RANDOM_SIZE * 2, server_key_exchange + params_start, params_len);
        to_sign_len = TLS_RANDOM_SIZE + TLS_RANDOM_SIZE + params_len;
        sig_len = DHE_SIG_BUF_SIZE;
        rc = noxtls_rsa_sign((const rsa_key_t *)ctx->server_private_rsa, to_sign, to_sign_len,
                             sig_buf, &sig_len, NOXTLS_HASH_SHA_256);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(alloc_aux) NOXTLS_SECURE_FREE(alloc_aux, DHE_TO_SIGN_SIZE + DHE_SIG_BUF_SIZE);
            if(server_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_key_exchange, 1024 + 320 + 512); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return rc;
        }
        server_key_exchange[offset++] = TLS_EC_POINT_UNCOMPRESSED;
        server_key_exchange[offset++] = 0x01;
        server_key_exchange[offset++] = (sig_len >> 8) & 0xFF;
        server_key_exchange[offset++] = sig_len & 0xFF;
        memcpy(server_key_exchange + offset, sig_buf, sig_len);
        offset += sig_len;
    } else {
        server_key_exchange[offset++] = 0x00;
        server_key_exchange[offset++] = 0x00;
        server_key_exchange[offset++] = 0x00;
        server_key_exchange[offset++] = 0x00;
    }

    params_len = offset - 4;
    server_key_exchange[1] = (params_len >> 16) & 0xFF;
    server_key_exchange[2] = (params_len >> 8) & 0xFF;
    server_key_exchange[3] = params_len & 0xFF;
    if(msg_out != NULL && msg_out_len != NULL && msg_out_size >= offset) {
        memcpy(msg_out, server_key_exchange, offset);
        *msg_out_len = offset;
    }
    rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, server_key_exchange, offset);
    if(alloc_aux) NOXTLS_SECURE_FREE(alloc_aux, DHE_TO_SIGN_SIZE + DHE_SIG_BUF_SIZE);
    if(server_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_key_exchange, 2048 + DHE_TO_SIGN_SIZE + DHE_SIG_BUF_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return rc;
}

noxtls_return_t tls12_dhe_recv_server_key_exchange(tls12_context_t *ctx, tls_dhe_context_t *dhe_ctx, const uint8_t *record_data, uint32_t record_len)
{
    const uint8_t *p = NULL;
    const uint8_t *g = NULL;
    uint32_t p_len = 0;
    uint32_t off;
    uint16_t len_p, len_g, len_Ys;
    noxtls_return_t rc;

    if(ctx == NULL || dhe_ctx == NULL || record_data == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_CLIENT) {
        return NOXTLS_RETURN_FAILED;
    }
    if(record_len < 4 || record_data[0] != TLS_HANDSHAKE_SERVER_KEY_EXCHANGE) {
        return NOXTLS_RETURN_FAILED;
    }

    off = 4;
    if(off + 2 > record_len) {
        return NOXTLS_RETURN_FAILED;
    }
    len_p = (uint16_t)((record_data[off] << 8) | record_data[off + 1]);
    off += 2;
    if(off + len_p + 2 > record_len) {
        return NOXTLS_RETURN_FAILED;
    }
    off += len_p;
    len_g = (uint16_t)((record_data[off] << 8) | record_data[off + 1]);
    off += 2;
    if(off + len_g + 2 > record_len) {
        return NOXTLS_RETURN_FAILED;
    }
    off += len_g;
    len_Ys = (uint16_t)((record_data[off] << 8) | record_data[off + 1]);
    off += 2;
    if(off + len_Ys > record_len) {
        return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_dh_ffdhe_params(dhe_ctx->named_group, &p, &g, &p_len) != NOXTLS_RETURN_SUCCESS ||
       len_p != p_len || len_g != p_len || len_Ys != p_len || p_len > dhe_ctx->p_len) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(dhe_ctx->server_public, record_data + off, p_len);
    off += p_len;
    uint32_t params_len = off - 4;

    if(off + 4 <= record_len) {
        uint16_t sig_len = (uint16_t)((record_data[off + 2] << 8) | record_data[off + 3]);
        if(sig_len > 0 && ctx->server_cert_parsed != NULL && off + 4 + sig_len <= record_len) {
            x509_certificate_t *cert = (x509_certificate_t *)ctx->server_cert_parsed;
            if(cert->rsa_modulus != NULL && cert->rsa_exponent != NULL) {
                uint32_t key_bytes = cert->rsa_modulus_len;
                rsa_key_size_t key_size = (key_bytes == 128) ? RSA_1024_BIT : (key_bytes == 256) ? RSA_2048_BIT :
                                          (key_bytes == 384) ? RSA_3072_BIT : (key_bytes == 512) ? RSA_4096_BIT : (rsa_key_size_t)0;
                if(key_bytes == 128 || key_bytes == 256 || key_bytes == 384 || key_bytes == 512) {
                    rsa_key_t rsa_key;
                    if(noxtls_rsa_key_init(&rsa_key, key_size) == NOXTLS_RETURN_SUCCESS) {
                        memcpy(rsa_key.n, cert->rsa_modulus, cert->rsa_modulus_len);
                        memcpy(rsa_key.e, cert->rsa_exponent, cert->rsa_exponent_len);
                        uint8_t *to_verify = (ctx->handshake_workspace != NULL) ? ctx->handshake_workspace : (uint8_t*)noxtls_malloc(DHE_TO_SIGN_SIZE);
                        if(to_verify != NULL && params_len <= DHE_TO_SIGN_SIZE - (TLS_RANDOM_SIZE * 2u)) {
                            memcpy(to_verify, ctx->client_random, TLS_RANDOM_SIZE);
                            memcpy(to_verify + TLS_RANDOM_SIZE, ctx->server_random, TLS_RANDOM_SIZE);
                            memcpy(to_verify + TLS_RANDOM_SIZE * 2, record_data + 4, params_len);
                            rc = noxtls_rsa_verify(&rsa_key, to_verify, (uint32_t)(TLS_RANDOM_SIZE + TLS_RANDOM_SIZE + params_len),
                                                    record_data + off + 4, sig_len, NOXTLS_HASH_SHA_256);
                            if(to_verify != ctx->handshake_workspace) NOXTLS_SECURE_FREE(to_verify, DHE_TO_SIGN_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                            noxtls_rsa_key_free(&rsa_key);
                            if(rc != NOXTLS_RETURN_SUCCESS) {
                                return NOXTLS_RETURN_FAILED;
                            }
                        } else {
                            if(to_verify != NULL && to_verify != ctx->handshake_workspace) NOXTLS_SECURE_FREE(to_verify, DHE_TO_SIGN_SIZE);
                            noxtls_rsa_key_free(&rsa_key);
                        }
                    }
                }
            }
        }
    }

    rc = noxtls_dh_generate_key(p, p_len, g, p_len, dhe_ctx->client_private, dhe_ctx->client_public);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_dh_shared_secret(dhe_ctx->client_private, p_len, dhe_ctx->server_public, p_len, p, p_len,
                                  dhe_ctx->premaster_secret);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    dhe_ctx->premaster_secret_len = p_len;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t tls12_dhe_send_client_key_exchange(tls12_context_t *ctx, tls_dhe_context_t *dhe_ctx)
{
    if(ctx == NULL || dhe_ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_CLIENT) {
        return NOXTLS_RETURN_FAILED;
    }
    uint8_t *client_key_exchange = ctx->handshake_workspace;
    if(client_key_exchange == NULL) {
        client_key_exchange = (uint8_t*)noxtls_malloc(1024);
        if(client_key_exchange == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    uint32_t offset = 0;
    uint32_t p_len = dhe_ctx->p_len;

    if(p_len + 6 > 1024) {
        if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, 512); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    client_key_exchange[offset++] = TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE;
    client_key_exchange[offset++] = 0x00;
    client_key_exchange[offset++] = 0x00;
    client_key_exchange[offset++] = 0x00;
    client_key_exchange[offset++] = (p_len >> 8) & 0xFF;
    client_key_exchange[offset++] = p_len & 0xFF;
    memcpy(client_key_exchange + offset, dhe_ctx->client_public, p_len);
    offset += p_len;
    uint32_t handshake_len = offset - 4;
    client_key_exchange[1] = (handshake_len >> 16) & 0xFF;
    client_key_exchange[2] = (handshake_len >> 8) & 0xFF;
    client_key_exchange[3] = handshake_len & 0xFF;
    noxtls_return_t rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, client_key_exchange, offset);
    if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, 512); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return rc;
}

noxtls_return_t tls12_dhe_recv_client_key_exchange(tls12_context_t *ctx, tls_dhe_context_t *dhe_ctx, const uint8_t *record_data, uint32_t record_len)
{
    const uint8_t *p = NULL;
    const uint8_t *g = NULL;
    uint32_t p_len = 0;
    uint32_t off;
    uint16_t len_Yc;
    noxtls_return_t rc;

    if(ctx == NULL || dhe_ctx == NULL || record_data == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    if(record_len < 6 || record_data[0] != TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE) {
        return NOXTLS_RETURN_FAILED;
    }
    off = 4;
    len_Yc = (uint16_t)((record_data[off] << 8) | record_data[off + 1]);
    off += 2;
    if(off + len_Yc > record_len || len_Yc != dhe_ctx->p_len) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(dhe_ctx->client_public, record_data + off, len_Yc);
    p_len = dhe_ctx->p_len;
    if(noxtls_dh_ffdhe_params(dhe_ctx->named_group, &p, &g, &p_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = noxtls_dh_shared_secret(dhe_ctx->server_private, p_len, dhe_ctx->client_public, len_Yc, p, p_len,
                                  dhe_ctx->premaster_secret);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    dhe_ctx->premaster_secret_len = p_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3: Encode Key Share entry
 * 
 * Format:
 * - Group (2 bytes)
 * - Key exchange length (2 bytes)
 * - Key exchange (uncompressed ECC point)
 */
noxtls_return_t tls13_key_share_encode(const tls_ecdhe_context_t *ecdhe_ctx, uint8_t *output, uint32_t *output_len)
{
    uint8_t public_key_encoded[133];  /* Max: 1 + 2*66 for P-521 */
    uint32_t public_key_len = sizeof(public_key_encoded);
    noxtls_return_t rc;
    uint32_t offset = 0;
    uint32_t required_len;
    
    if(ecdhe_ctx == NULL || output == NULL || output_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Get encoded public key */
    rc = tls_ecdhe_get_public_key_encoded((tls_ecdhe_context_t*)ecdhe_ctx, public_key_encoded, &public_key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    required_len = 2 + 2 + public_key_len;  /* Group + length + key exchange */
    
    if(*output_len < required_len) {
        *output_len = required_len;
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Group (2 bytes) */
    output[offset++] = (ecdhe_ctx->named_group >> 8) & 0xFF;
    output[offset++] = ecdhe_ctx->named_group & 0xFF;
    
    /* Key exchange length (2 bytes) */
    output[offset++] = (public_key_len >> 8) & 0xFF;
    output[offset++] = public_key_len & 0xFF;
    
    /* Key exchange */
    memcpy(output + offset, public_key_encoded, public_key_len);
    offset += public_key_len;
    
    *output_len = offset;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3: Decode Key Share entry
 */
noxtls_return_t tls13_key_share_decode(const uint8_t *encoded, uint32_t encoded_len, uint16_t named_group, ecc_point_t *public_key)
{
    uint16_t group;
    uint16_t key_exchange_len;
    ecc_curve_t curve_type;
    noxtls_return_t rc;
    
    if(encoded == NULL || public_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(encoded_len < 4) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Group (2 bytes) */
    group = (encoded[0] << 8) | encoded[1];
    
    /* Verify group matches */
    if(group != named_group) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Key exchange length (2 bytes) */
    key_exchange_len = (encoded[2] << 8) | encoded[3];
    
    {
        uint32_t required_len = (uint32_t)key_exchange_len + 4u;
        if(encoded_len < required_len) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    
    /* X25519 key share is 32 raw bytes; decode API returns ECC point, so not applicable */
    if(named_group == TLS_NAMED_GROUP_X25519) {
        if(key_exchange_len != TLS_RANDOM_SIZE) {
            return NOXTLS_RETURN_FAILED;
        }
        /* Caller should use key_exchange bytes directly with tls_ecdhe_compute_shared_secret_x25519 */
        return NOXTLS_RETURN_FAILED;  /* Decode to ecc_point_t not supported for X25519 */
    }
    
    /* Map named group to curve type */
    rc = tls_named_group_to_ecc_curve(named_group, &curve_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    /* Decode public key */
    return tls_decode_ecc_point_uncompressed(encoded + 4, key_exchange_len, public_key, curve_type);
}

/**
 * @brief TLS 1.3: Process client key share
 * 
 * This function extracts the client's key share from the Client Hello
 * and computes the shared secret.
 */
noxtls_return_t tls13_process_client_key_share(tls13_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx)
{
    ecc_point_t peer_public_key;
    noxtls_return_t rc;
    
    if(ctx == NULL || ecdhe_ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if(ctx->client_key_shares == NULL || ctx->client_key_shares_count == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Find matching key share */
    uint32_t i;
    const tls13_key_share_entry_t *client_key_share = NULL;
    for(i = 0; i < ctx->client_key_shares_count; i++) {
        if(ctx->client_key_shares[i].group == ecdhe_ctx->named_group) {
            client_key_share = &ctx->client_key_shares[i];
            break;
        }
    }
    
    if(client_key_share == NULL) {
        return NOXTLS_RETURN_FAILED;  /* No matching key share found */
    }
    
    if(ecdhe_ctx->named_group == TLS_NAMED_GROUP_X25519) {
        if(client_key_share->key_exchange_len != NOXTLS_X25519_KEY_SIZE) {
            return NOXTLS_RETURN_FAILED;
        }
        return tls_ecdhe_compute_shared_secret_x25519(ecdhe_ctx, client_key_share->key_exchange);
    }
    
    /* Decode client's public key (raw key_exchange bytes) */
    ecc_curve_t curve_type;
    rc = tls_named_group_to_ecc_curve(ecdhe_ctx->named_group, &curve_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls_decode_ecc_point_uncompressed(client_key_share->key_exchange,
                                           client_key_share->key_exchange_len,
                                           &peer_public_key,
                                           curve_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    /* Compute shared secret */
    return tls_ecdhe_compute_shared_secret(ecdhe_ctx, &peer_public_key);
}

/**
 * @brief TLS 1.3: Process server key share
 * 
 * This function extracts the server's key share from the Server Hello
 * and computes the shared secret.
 */
noxtls_return_t tls13_process_server_key_share(const tls13_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx)
{
    ecc_point_t peer_public_key;
    noxtls_return_t rc;
    
    if(ctx == NULL || ecdhe_ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_CLIENT) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if(ctx->server_key_share == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Verify group matches */
    if(ctx->server_key_share->group != ecdhe_ctx->named_group) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if(ecdhe_ctx->named_group == TLS_NAMED_GROUP_X25519) {
        if(ctx->server_key_share->key_exchange_len != NOXTLS_X25519_KEY_SIZE) {
            return NOXTLS_RETURN_FAILED;
        }
        return tls_ecdhe_compute_shared_secret_x25519(ecdhe_ctx, ctx->server_key_share->key_exchange);
    }
    
    /* Decode server's public key (raw key_exchange bytes) */
    ecc_curve_t curve_type;
    rc = tls_named_group_to_ecc_curve(ecdhe_ctx->named_group, &curve_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls_decode_ecc_point_uncompressed(ctx->server_key_share->key_exchange,
                                           ctx->server_key_share->key_exchange_len,
                                           &peer_public_key,
                                           curve_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(ecdhe_ctx->ephemeral_key.d != NULL && ecdhe_ctx->ephemeral_key.curve != NULL) {
        uint32_t size = ecdhe_ctx->ephemeral_key.curve->size;
        noxtls_debug_printf("[TLS13_DEBUG] ecdhe d=");
        for(uint32_t i = 0; i < size; i++) {
            noxtls_debug_printf("%02X", ecdhe_ctx->ephemeral_key.d[i]);
        }
        noxtls_debug_printf("\n");
        noxtls_debug_printf("[TLS13_DEBUG] ecdhe peer_x=");
        for(uint32_t i = 0; i < size; i++) {
            noxtls_debug_printf("%02X", peer_public_key.x[i]);
        }
        noxtls_debug_printf("\n");
        noxtls_debug_printf("[TLS13_DEBUG] ecdhe peer_y=");
        for(uint32_t i = 0; i < size; i++) {
            noxtls_debug_printf("%02X", peer_public_key.y[i]);
        }
        noxtls_debug_printf("\n");
    }
    
    /* Compute shared secret */
    return tls_ecdhe_compute_shared_secret(ecdhe_ctx, &peer_public_key);
}

