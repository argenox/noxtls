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
* File:    noxtls_tls_key_exchange.c
* Summary: TLS Key Exchange Implementation (ECDHE, etc.)
*
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>
#include "common/noxtls_memory.h"

#ifndef NOXTLS_TLS_KEY_EXCHANGE_DEBUG
#define NOXTLS_TLS_KEY_EXCHANGE_DEBUG 0
#endif
#if NOXTLS_TLS_KEY_EXCHANGE_DEBUG
#include <stdio.h>
#define KEX_FFLUSH(...) ((void)0)
#else
#define KEX_FFLUSH(...) ((void)0)
#endif
#include "common/noxtls_ct.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_tls_key_exchange.h"
#include "noxtls_tls_common.h"
#include "noxtls_tls12.h"
#include "noxtls_tls13.h"
#include "pkc/ecdh/noxtls_ecdh.h"
#include "pkc/x25519/noxtls_x25519.h"
#include "pkc/x448/noxtls_x448.h"
#include "pkc/rsa/noxtls_rsa.h"
#include "pkc/dh/noxtls_dh.h"
#include "certs/noxtls_x509.h"
#include "mdigest/noxtls_hash.h"
#include "noxtls_ct.h"

#define DHE_TO_SIGN_SIZE  (32U + 32U + 4096U)
#define DHE_SIG_BUF_SIZE  512U

/**
 * @brief Map TLS named group to ECC curve type.
 * @param[in] named_group IANA TLS named group identifier.
 * @param[out] curve_type Receives the mapped `ecc_curve_t` (placeholder for X25519/X448).
 * @return `NOXTLS_RETURN_SUCCESS` if recognized; `NOXTLS_RETURN_NULL` if @p curve_type is NULL; `NOXTLS_RETURN_FAILED` if unsupported.
 */
noxtls_return_t noxtls_tls_named_group_to_ecc_curve(uint16_t named_group, ecc_curve_t *curve_type)
{
    if (curve_type == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    switch (named_group) {
        case TLS_NAMED_GROUP_SECP256R1:
            *curve_type = NOXTLS_ECC_SECP256R1;
            return NOXTLS_RETURN_SUCCESS;
            
        case TLS_NAMED_GROUP_SECP384R1:
            *curve_type = NOXTLS_ECC_SECP384R1;
            return NOXTLS_RETURN_SUCCESS;
            
        case TLS_NAMED_GROUP_SECP521R1:
            *curve_type = NOXTLS_ECC_SECP521R1;
            return NOXTLS_RETURN_SUCCESS;
            
        case TLS_NAMED_GROUP_X25519:
            *curve_type = NOXTLS_ECC_SECP256R1;  /* unused for X25519; callers branch on named_group */
            return NOXTLS_RETURN_SUCCESS;
        case TLS_NAMED_GROUP_X448:
        default:
            return NOXTLS_RETURN_FAILED;
    }
}

/**
 * @brief Map ECC curve type to TLS named group.
 * @param[in] curve_type Internal NIST curve type.
 * @param[out] named_group Receives the TLS named group value.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p named_group is NULL; `NOXTLS_RETURN_FAILED` if unmapped.
 */
noxtls_return_t noxtls_tls_ecc_curve_to_named_group(ecc_curve_t curve_type, uint16_t *named_group)
{
    if (named_group == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    switch (curve_type) {
        case NOXTLS_ECC_SECP256R1:
            *named_group = TLS_NAMED_GROUP_SECP256R1;
            return NOXTLS_RETURN_SUCCESS;
            
        case NOXTLS_ECC_SECP384R1:
            *named_group = TLS_NAMED_GROUP_SECP384R1;
            return NOXTLS_RETURN_SUCCESS;
            
        case NOXTLS_ECC_SECP521R1:
            *named_group = TLS_NAMED_GROUP_SECP521R1;
            return NOXTLS_RETURN_SUCCESS;
            
        default:
            return NOXTLS_RETURN_FAILED;
    }
}

/**
 * @brief Encode ECC point in uncompressed format for TLS (0x04u || X || Y).
 * @param[in] point ECC point to encode.
 * @param[out] output Output buffer.
 * @param[in,out] output_len On input, size of @p output; on success, encoded length; if too small, set to required length.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` if @p output is too small.
 */
noxtls_return_t noxtls_tls_encode_ecc_point_uncompressed(const ecc_point_t *point, uint8_t *output, uint32_t *output_len)
{
    if ((point == NULL) || (output == NULL) || (output_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    uint32_t required_len = (uint32_t)(1U + (2U * point->size));  /* 0x04 + x + y */
    
    if (*output_len < required_len) {
        *output_len = required_len;
        return NOXTLS_RETURN_FAILED;
    }
    
    uint32_t offset = 0U;
    
    /* Uncompressed point format indicator */
    output[offset] = 0x04U;
    offset += 1U;
    
    /* X-coordinate (big-endian) */
    noxtls_copy_u8(&output[offset], (size_t)(*output_len), point->x, (size_t)(point->size));
    offset += point->size;
    
    /* Y-coordinate (big-endian) */
    noxtls_copy_u8(&output[offset], (size_t)(*output_len), point->y, (size_t)(point->size));
    offset += point->size;
    
    *output_len = offset;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Decode ECC point from uncompressed TLS format (0x04u || X || Y).
 * @param[in] encoded Encoded point bytes.
 * @param[in] encoded_len Length of @p encoded.
 * @param[out] point Output ECC point (initialized by this function).
 * @param[in] curve_type Curve used to determine expected coordinate sizes.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on malformed input.
 */
noxtls_return_t noxtls_tls_decode_ecc_point_uncompressed(const uint8_t *encoded, uint32_t encoded_len, ecc_point_t *point, ecc_curve_t curve_type)
{
    uint32_t expected_size = 0U;
    
    if ((encoded == NULL) || (point == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Determine expected point size based on curve */
    switch (curve_type) {
        case NOXTLS_ECC_SECP256R1:
            expected_size = 32U;
            break;
        case NOXTLS_ECC_SECP384R1:
            expected_size = 48U;
            break;
        case NOXTLS_ECC_SECP521R1:
            expected_size = 66U;  /* (521+7)/8 = 66 */
            break;
        default:
            return NOXTLS_RETURN_FAILED;
    }
    
    uint32_t required_len = (uint32_t)(1U + (2U * expected_size));  /* 0x04 + x + y */
    
    if (encoded_len != required_len) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Check uncompressed format indicator */
    if (encoded[0] != TLS_EC_POINT_UNCOMPRESSED) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Initialize point */
    (void)noxtls_ecc_point_init(point, expected_size);
    point->size = expected_size;
    
    /* Decode x-coordinate */
    noxtls_copy_u8(point->x, sizeof(point->x), &encoded[1], (size_t)expected_size);
    
    /* Decode y-coordinate */
    noxtls_copy_u8(point->y, sizeof(point->y), &encoded[1U + expected_size], (size_t)expected_size);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize ECDHE context for a named group.
 * @param[out] ctx Context to initialize (zeroed first).
 * @param[in] named_group TLS named group for this handshake.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p ctx is NULL; other codes on ECC setup failure.
 */
noxtls_return_t noxtls_tls_ecdhe_context_init(tls_ecdhe_context_t *ctx, uint16_t named_group)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    noxtls_secure_zero((ctx), sizeof(tls_ecdhe_context_t));
    ctx->named_group = named_group;
    
#if !NOXTLS_FEATURE_X25519
    if (named_group == TLS_NAMED_GROUP_X25519) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
#endif
#if !NOXTLS_FEATURE_X448
    if (named_group == TLS_NAMED_GROUP_X448) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
#endif
    if ((named_group == TLS_NAMED_GROUP_X25519) || (named_group == TLS_NAMED_GROUP_X448)) {
        /* RFC 7748 Montgomery groups: no ECC key; curve_type unused. */
        return NOXTLS_RETURN_SUCCESS;
    }
    
    /* Map named group to curve type */
    rc = noxtls_tls_named_group_to_ecc_curve(named_group, &ctx->curve_type);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    /* Initialize ephemeral key */
    rc = noxtls_ecc_key_init(&ctx->ephemeral_key, ctx->curve_type);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Free ECDHE context allocations and zero the structure.
 * @param[in,out] ctx Context to clear.
 * @return `NOXTLS_RETURN_SUCCESS`; `NOXTLS_RETURN_NULL` if @p ctx is NULL.
 */
noxtls_return_t noxtls_tls_ecdhe_context_free(tls_ecdhe_context_t *ctx)
{
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if ((ctx->named_group != TLS_NAMED_GROUP_X25519) && (ctx->named_group != TLS_NAMED_GROUP_X448)) {
        (void)noxtls_ecc_key_free(&ctx->ephemeral_key);
    } else if (ctx->named_group == TLS_NAMED_GROUP_X25519) {
        noxtls_secure_zero((ctx->x25519_private_key), sizeof(ctx->x25519_private_key));
        noxtls_secure_zero((ctx->x25519_public_key), sizeof(ctx->x25519_public_key));
    } else {
        noxtls_secure_zero((ctx->x448_private_key), sizeof(ctx->x448_private_key));
        noxtls_secure_zero((ctx->x448_public_key), sizeof(ctx->x448_public_key));
    }
    
    /* Free premaster secret (TLS 1.2) */
    if (ctx->premaster_secret != NULL) {
        noxtls_secure_zero((ctx->premaster_secret), ((size_t)ctx->premaster_secret_len));
        (void)noxtls_free(ctx->premaster_secret);
        ctx->premaster_secret = NULL;
        ctx->premaster_secret_len = 0U;
    }
    
    /* Free shared secret (TLS 1.3) */
    if (ctx->shared_secret != NULL) {
        noxtls_secure_zero((ctx->shared_secret), ((size_t)ctx->shared_secret_len));
        (void)noxtls_free(ctx->shared_secret);
        ctx->shared_secret = NULL;
        ctx->shared_secret_len = 0U;
    }
    
    noxtls_secure_zero((ctx), sizeof(tls_ecdhe_context_t));
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generate ephemeral key pair for ECDHE.
 * @param[in,out] ctx Initialized context; receives new key material.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p ctx is NULL; `NOXTLS_RETURN_FAILED` on failure.
 */
noxtls_return_t noxtls_tls_ecdhe_generate_ephemeral_key(tls_ecdhe_context_t *ctx)
{
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
#if NOXTLS_FEATURE_X25519
    if (ctx->named_group == TLS_NAMED_GROUP_X25519) { return noxtls_x25519_generate_key(ctx->x25519_private_key, ctx->x25519_public_key); }
#else
    if (ctx->named_group == TLS_NAMED_GROUP_X25519) { return NOXTLS_RETURN_NOT_SUPPORTED; }
#endif
#if NOXTLS_FEATURE_X448
    if (ctx->named_group == TLS_NAMED_GROUP_X448) { return noxtls_x448_generate_key(ctx->x448_private_key, ctx->x448_public_key); }
#else
    if (ctx->named_group == TLS_NAMED_GROUP_X448) { return NOXTLS_RETURN_NOT_SUPPORTED; }
#endif
    
    if (ctx->ephemeral_key.curve == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    /*
     * noxtls_ecc_key_generate() reinitializes the key structure.
     * Free any previously initialized key material first to avoid leaks.
     */
    (void)noxtls_ecc_key_free(&ctx->ephemeral_key);
    
    /* Generate ephemeral key pair */
    return noxtls_ecc_key_generate(&ctx->ephemeral_key, ctx->curve_type);
}

/**
 * @brief Compute ECDH shared secret from peer's uncompressed ECC public key (NIST curves).
 * @param[in,out] ctx Local ephemeral key; receives heap-allocated `shared_secret`.
 * @param[in] peer_public_key Peer's public point on the same curve.
 * @return `NOXTLS_RETURN_SUCCESS` on success; a specific ECDH return code on
 * cryptographic failure; `NOXTLS_RETURN_NOT_ENOUGH_MEMORY` on allocation
 * failure.  `ctx->last_ecdh_diagnostic` retains non-secret provenance.
 */
noxtls_return_t noxtls_tls_ecdhe_compute_shared_secret(tls_ecdhe_context_t *ctx, const ecc_point_t *peer_public_key)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint8_t *secret_buffer = NULL;
    uint32_t secret_len = 0U;
    
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if (peer_public_key == NULL) {
        ctx->last_ecdh_diagnostic.stage = NOXTLS_ECDH_DIAGNOSTIC_ARGUMENT;
        ctx->last_ecdh_diagnostic.internal_rc = NOXTLS_RETURN_NULL;
        return NOXTLS_RETURN_NULL;
    }
    
    if (ctx->ephemeral_key.curve == NULL) {
        ctx->last_ecdh_diagnostic.stage = NOXTLS_ECDH_DIAGNOSTIC_PRIVATE_KEY;
        ctx->last_ecdh_diagnostic.internal_rc =
            NOXTLS_RETURN_ECDH_PRIVATE_KEY_INVALID;
        return NOXTLS_RETURN_ECDH_PRIVATE_KEY_INVALID;
    }
    
    secret_len = ctx->ephemeral_key.curve->size;
    secret_buffer = (uint8_t*)NOXTLS_MALLOC(secret_len);
    if (secret_buffer == NULL) {
        ctx->last_ecdh_diagnostic.stage = NOXTLS_ECDH_DIAGNOSTIC_ALLOCATION;
        ctx->last_ecdh_diagnostic.internal_rc = NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    
    /* Compute shared secret using ECDH */
    rc = noxtls_ecdh_compute_shared_secret_ex(&ctx->ephemeral_key,
                                              peer_public_key,
                                              secret_buffer,
                                              &secret_len,
                                              &ctx->last_ecdh_diagnostic);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(secret_buffer);
        return rc;
    }
    
    /* Store shared secret (for TLS 1.3) */
    if (ctx->shared_secret != NULL) {
        noxtls_secure_zero((ctx->shared_secret), ((size_t)ctx->shared_secret_len));
        (void)noxtls_free(ctx->shared_secret);
    }
    
    ctx->shared_secret = secret_buffer;
    ctx->shared_secret_len = secret_len;

    (void)noxtls_debug_printf((const uint8_t *)"[TLS12_DEBUG] ecdhe shared_secret_len=%u shared[0..3]=%02X%02X%02X%02X\n",
                          ctx->shared_secret_len,
                          (ctx->shared_secret_len > 0U) ? ctx->shared_secret[0] : 0U,
                          (ctx->shared_secret_len > 1U) ? ctx->shared_secret[1] : 0U,
                          (ctx->shared_secret_len > 2U) ? ctx->shared_secret[2] : 0U,
                          (ctx->shared_secret_len > 3U) ? ctx->shared_secret[3] : 0U);
    KEX_FFLUSH(stdout);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Get encoded public key for transmission (raw Montgomery bytes or uncompressed ECC point).
 * @param[in] ctx Context with generated keys.
 * @param[out] output Buffer for encoded public key.
 * @param[in,out] output_len On input, size of @p output; on success, written length.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` if keys missing or buffer too small.
 */
noxtls_return_t noxtls_tls_ecdhe_get_public_key_encoded(const tls_ecdhe_context_t *ctx, uint8_t *output, uint32_t *output_len)
{
    if ((ctx == NULL) || (output == NULL) || (output_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    if (ctx->named_group == TLS_NAMED_GROUP_X25519) {
        if (*output_len < NOXTLS_X25519_KEY_SIZE) {
            *output_len = NOXTLS_X25519_KEY_SIZE;
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_copy_u8(output, (size_t)(*output_len), ctx->x25519_public_key, (size_t)(NOXTLS_X25519_KEY_SIZE));
        *output_len = NOXTLS_X25519_KEY_SIZE;
        return NOXTLS_RETURN_SUCCESS;
    }
    if (ctx->named_group == TLS_NAMED_GROUP_X448) {
        if (*output_len < NOXTLS_X448_KEY_SIZE) {
            *output_len = NOXTLS_X448_KEY_SIZE;
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_copy_u8(output, (size_t)(*output_len), ctx->x448_public_key, (size_t)(NOXTLS_X448_KEY_SIZE));
        *output_len = NOXTLS_X448_KEY_SIZE;
        return NOXTLS_RETURN_SUCCESS;
    }
    
    if (ctx->ephemeral_key.curve == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    return noxtls_tls_encode_ecc_point_uncompressed(&ctx->ephemeral_key.Q, output, output_len);
}

/**
 * @brief Compute shared secret from peer's X25519 public key (32 bytes).
 * @param[in,out] ctx Context for `TLS_NAMED_GROUP_X25519` with local key generated.
 * @param[in] peer_public_key Peer's 32-byte public key.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on wrong group, all-zero secret, or allocation failure.
 */
noxtls_return_t noxtls_tls_ecdhe_compute_shared_secret_x25519(tls_ecdhe_context_t *ctx, const uint8_t *peer_public_key)
{
    static const uint8_t x25519_zero_secret[NOXTLS_X25519_KEY_SIZE] = { 0 };
    uint8_t *secret_buffer = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    if ((ctx == NULL) || (peer_public_key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    if (ctx->named_group != TLS_NAMED_GROUP_X25519) {
        return NOXTLS_RETURN_FAILED;
    }
    
    secret_buffer = (uint8_t*)NOXTLS_MALLOC(NOXTLS_X25519_KEY_SIZE);
    if (secret_buffer == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
#if NOXTLS_FEATURE_X25519
    rc = noxtls_x25519_shared_secret(ctx->x25519_private_key, peer_public_key, secret_buffer);
#else
    rc = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    if (rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(secret_buffer);
        return rc;
    }
    if (noxtls_secret_memcmp(secret_buffer, x25519_zero_secret, (size_t)(NOXTLS_X25519_KEY_SIZE)) == 0) {
        NOXTLS_SECURE_FREE(secret_buffer, NOXTLS_X25519_KEY_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    
    if (ctx->shared_secret != NULL) {
        noxtls_secure_zero((ctx->shared_secret), ((size_t)ctx->shared_secret_len));
        (void)noxtls_free(ctx->shared_secret);
    }
    
    ctx->shared_secret = secret_buffer;
    ctx->shared_secret_len = NOXTLS_X25519_KEY_SIZE;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Compute shared secret from peer's X448 public key (56 bytes).
 * @param[in,out] ctx Context for `TLS_NAMED_GROUP_X448` with local key generated.
 * @param[in] peer_public_key Peer's 56-byte public key.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on wrong group, all-zero secret, or allocation failure.
 */
noxtls_return_t noxtls_tls_ecdhe_compute_shared_secret_x448(tls_ecdhe_context_t *ctx, const uint8_t *peer_public_key)
{
    static const uint8_t x448_zero_secret[NOXTLS_X448_KEY_SIZE] = { 0 };
    uint8_t *secret_buffer = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((ctx == NULL) || (peer_public_key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (ctx->named_group != TLS_NAMED_GROUP_X448) {
        return NOXTLS_RETURN_FAILED;
    }

    secret_buffer = (uint8_t*)NOXTLS_MALLOC(NOXTLS_X448_KEY_SIZE);
    if (secret_buffer == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

#if NOXTLS_FEATURE_X448
    rc = noxtls_x448_shared_secret(ctx->x448_private_key, peer_public_key, secret_buffer);
#else
    rc = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    if (rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(secret_buffer);
        return rc;
    }
    if (noxtls_secret_memcmp(secret_buffer, x448_zero_secret, (size_t)(NOXTLS_X448_KEY_SIZE)) == 0) {
        NOXTLS_SECURE_FREE(secret_buffer, NOXTLS_X448_KEY_SIZE);
        return NOXTLS_RETURN_FAILED;
    }

    if (ctx->shared_secret != NULL) {
        noxtls_secure_zero((ctx->shared_secret), ((size_t)ctx->shared_secret_len));
        (void)noxtls_free(ctx->shared_secret);
    }
    ctx->shared_secret = secret_buffer;
    ctx->shared_secret_len = NOXTLS_X448_KEY_SIZE;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 server: send ECDHE ServerKeyExchange (optional RSA signature over transcript prefix + params).
 * @param[in,out] ctx TLS 1.2 server context.
 * @param[in,out] ecdhe_ctx ECDHE state with ephemeral public key.
 * @return `NOXTLS_RETURN_SUCCESS` if the record was sent; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on role or build errors; `NOXTLS_RETURN_NOT_ENOUGH_MEMORY` on allocation failure.
 */
noxtls_return_t noxtls_tls12_ecdhe_send_server_key_exchange(tls12_context_t *ctx, const tls_ecdhe_context_t *ecdhe_ctx)
{
    if ((ctx == NULL) || (ecdhe_ctx == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    /* workspace layout: server_key_exchange 0..1023, to_sign 1024..1343, sig_buf 1344..1855 */
    uint8_t *server_key_exchange = ctx->handshake_workspace;
    uint8_t *to_sign = (ctx->handshake_workspace != NULL) ? (&ctx->handshake_workspace[1024]) : NULL;
    uint8_t *sig_buf = (ctx->handshake_workspace != NULL) ? (&ctx->handshake_workspace[1344]) : NULL;
    if (server_key_exchange == NULL) {
        server_key_exchange = (uint8_t*)NOXTLS_MALLOC(1024 + 320 + 512);
        if (server_key_exchange == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        to_sign = &server_key_exchange[1024];
        sig_buf = &server_key_exchange[1344];
    }
    uint32_t offset = 0U;
    uint8_t public_key_encoded[133];  /* Max: 1 + 2*66 for P-521 */
    uint32_t public_key_len = (uint32_t)sizeof(public_key_encoded);
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t params_start;  /* offset of curve_type (after handshake header) */
    uint32_t params_len = 0U;
    uint32_t to_sign_len = 0U;
    uint32_t sig_len = 0U;

    /* Build Server Key Exchange noxtls_message */
    server_key_exchange[offset] = TLS_HANDSHAKE_SERVER_KEY_EXCHANGE;
    offset += 1U;
    server_key_exchange[offset] = 0x00U;
    offset += 1U;  /* Length (3 bytes) - placeholder */
    server_key_exchange[offset] = 0x00U;
    offset += 1U;
    server_key_exchange[offset] = 0x00U;
    offset += 1U;

    params_start = offset;
    /* Curve type: named_curve (0x03u) */
    server_key_exchange[offset] = TLS_EC_CURVE_TYPE_NAMED;
    offset += 1U;
    server_key_exchange[offset] = (uint8_t)(((uint32_t)ecdhe_ctx->named_group >>8U) & 0xFFU);
    offset += 1U;
    server_key_exchange[offset] = (uint8_t)(ecdhe_ctx->named_group & 0xFFU);
    offset += 1U;
    noxtls_secure_zero((public_key_encoded), sizeof(public_key_encoded));
    rc = noxtls_tls_ecdhe_get_public_key_encoded(ecdhe_ctx, public_key_encoded, &public_key_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        if (server_key_exchange != ctx->handshake_workspace) { NOXTLS_SECURE_FREE(server_key_exchange, 1024U + 320U + 512U); } else if (ctx->handshake_workspace != NULL) { noxtls_secure_zero((ctx->handshake_workspace), (size_t)(TLS_HANDSHAKE_WORKSPACE_SIZE)); }
                    else {
                        /* MISRA 15.7: no remaining alternative */
                    }
        return rc;
    }
    server_key_exchange[offset] = (uint8_t)(public_key_len & 0xFFU);
    offset += 1U;
    noxtls_copy_u8(&server_key_exchange[offset], (size_t)(1024 + 320 + 512), public_key_encoded, (size_t)(public_key_len));
    offset += public_key_len;
    params_len = offset - params_start;

    if ((ctx->crypto_provider != NULL) && (ctx->crypto_provider->ops != NULL) && (ctx->crypto_provider->ops->rsa_sign != NULL) && (ctx->server_private_key_handle != NULL)) {
        if (320U < (uint32_t)(TLS_RANDOM_SIZE + TLS_RANDOM_SIZE + params_len)) {
            if (server_key_exchange != ctx->handshake_workspace) { NOXTLS_SECURE_FREE(server_key_exchange, 1024U + 320U + 512U); } else if (ctx->handshake_workspace != NULL) { noxtls_secure_zero((ctx->handshake_workspace), (size_t)(TLS_HANDSHAKE_WORKSPACE_SIZE)); }
                        else {
                            /* MISRA 15.7: no remaining alternative */
                        }
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_copy_u8(to_sign, (size_t)320U, ctx->client_random, (size_t)(TLS_RANDOM_SIZE));
        noxtls_copy_u8(&to_sign[TLS_RANDOM_SIZE], (size_t)320U - (size_t)(TLS_RANDOM_SIZE), ctx->server_random, (size_t)(TLS_RANDOM_SIZE));
        noxtls_copy_u8(&to_sign[((size_t)TLS_RANDOM_SIZE * 2U)], (size_t)320U - (size_t)(((size_t)TLS_RANDOM_SIZE * 2U)), &server_key_exchange[params_start], (size_t)(params_len));
        to_sign_len = TLS_RANDOM_SIZE + TLS_RANDOM_SIZE + params_len;
        sig_len = 512U;
        rc = ctx->crypto_provider->ops->rsa_sign(ctx->crypto_provider->ctx, ctx->server_private_key_handle,
                to_sign, to_sign_len, sig_buf, &sig_len, (noxtls_crypto_hash_algo_t)NOXTLS_HASH_SHA_256);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            if (server_key_exchange != ctx->handshake_workspace) { NOXTLS_SECURE_FREE(server_key_exchange, 1024U + 320U + 512U); } else if (ctx->handshake_workspace != NULL) { noxtls_secure_zero((ctx->handshake_workspace), (size_t)(TLS_HANDSHAKE_WORKSPACE_SIZE)); }
                        else {
                            /* MISRA 15.7: no remaining alternative */
                        }
            return rc;
        }
        server_key_exchange[offset] = TLS_EC_POINT_UNCOMPRESSED;
        offset += 1U;
        server_key_exchange[offset] = 0x01U;
        offset += 1U;
        server_key_exchange[offset] = (uint8_t)((sig_len >>8U) & 0xFFU);
        offset += 1U;
        server_key_exchange[offset] = (uint8_t)(sig_len & 0xFFU);
        offset += 1U;
        if(((offset + sig_len) > TLS_CLIENT_HELLO_BASE_SIZE)) {
            if (server_key_exchange != ctx->handshake_workspace) { NOXTLS_SECURE_FREE(server_key_exchange, 1024U + 320U + 512U); } else if (ctx->handshake_workspace != NULL) { noxtls_secure_zero((ctx->handshake_workspace), (size_t)(TLS_HANDSHAKE_WORKSPACE_SIZE)); }
                        else {
                            /* MISRA 15.7: no remaining alternative */
                        }
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_copy_u8(&server_key_exchange[offset], (size_t)1024U - (size_t)(offset), sig_buf, (size_t)(sig_len));
        offset += sig_len;
    } else if (ctx->server_private_rsa != NULL) {
        /* TLS 1.2: sign Hash(&client_random[server_random + params]); use RSA PKCS#1 with SHA256 */
        if (320U < (uint32_t)(TLS_RANDOM_SIZE + TLS_RANDOM_SIZE + params_len)) {
            if (server_key_exchange != ctx->handshake_workspace) { NOXTLS_SECURE_FREE(server_key_exchange, 1024U + 320U + 512U); } else if (ctx->handshake_workspace != NULL) { noxtls_secure_zero((ctx->handshake_workspace), (size_t)(TLS_HANDSHAKE_WORKSPACE_SIZE)); }
                        else {
                            /* MISRA 15.7: no remaining alternative */
                        }
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_copy_u8(to_sign, (size_t)320U, ctx->client_random, (size_t)(TLS_RANDOM_SIZE));
        noxtls_copy_u8(&to_sign[TLS_RANDOM_SIZE], (size_t)320U - (size_t)(TLS_RANDOM_SIZE), ctx->server_random, (size_t)(TLS_RANDOM_SIZE));
        noxtls_copy_u8(&to_sign[((size_t)TLS_RANDOM_SIZE * 2U)], (size_t)320U - (size_t)(((size_t)TLS_RANDOM_SIZE * 2U)), &server_key_exchange[params_start], (size_t)(params_len));
        to_sign_len = TLS_RANDOM_SIZE + TLS_RANDOM_SIZE + params_len;
        sig_len = 512U;
#if NOXTLS_FEATURE_RSA
        rc = noxtls_rsa_sign((const rsa_key_t *)ctx->server_private_rsa, to_sign, to_sign_len,
                             sig_buf, &sig_len, NOXTLS_HASH_SHA_256);
#else
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        if (rc != NOXTLS_RETURN_SUCCESS) {
            if (server_key_exchange != ctx->handshake_workspace) { NOXTLS_SECURE_FREE(server_key_exchange, 1024U + 320U + 512U); } else if (ctx->handshake_workspace != NULL) { noxtls_secure_zero((ctx->handshake_workspace), (size_t)(TLS_HANDSHAKE_WORKSPACE_SIZE)); }
                        else {
                            /* MISRA 15.7: no remaining alternative */
                        }
            return rc;
        }
        /* Signature algorithm: sha256(4) + rsa(1) = 0x0401u */
        server_key_exchange[offset] = TLS_EC_POINT_UNCOMPRESSED;
        offset += 1U;
        server_key_exchange[offset] = 0x01U;
        offset += 1U;
        server_key_exchange[offset] = (uint8_t)((sig_len >>8U) & 0xFFU);
        offset += 1U;
        server_key_exchange[offset] = (uint8_t)(sig_len & 0xFFU);
        offset += 1U;
        if(((offset + sig_len) > TLS_CLIENT_HELLO_BASE_SIZE)) {
            if (server_key_exchange != ctx->handshake_workspace) { NOXTLS_SECURE_FREE(server_key_exchange, 1024U + 320U + 512U); } else if (ctx->handshake_workspace != NULL) { noxtls_secure_zero((ctx->handshake_workspace), (size_t)(TLS_HANDSHAKE_WORKSPACE_SIZE)); }
                        else {
                            /* MISRA 15.7: no remaining alternative */
                        }
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_copy_u8(&server_key_exchange[offset], (size_t)1024U - (size_t)(offset), sig_buf, (size_t)(sig_len));
        offset += sig_len;
    } else {
        server_key_exchange[offset] = 0x00U;
        offset += 1U;
        server_key_exchange[offset] = 0x00U;
        offset += 1U;
        server_key_exchange[offset] = 0x00U;
        offset += 1U;
        server_key_exchange[offset] = 0x00U;
        offset += 1U;
    }

    uint32_t handshake_len = (uint32_t)(offset - 4U);
    server_key_exchange[1] = (uint8_t)((handshake_len >>16U) & 0xFFU);
    server_key_exchange[2] = (uint8_t)((handshake_len >>8U) & 0xFFU);
    server_key_exchange[3] = (uint8_t)(handshake_len & 0xFFU);
    rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, server_key_exchange, offset);
    if (server_key_exchange != ctx->handshake_workspace) { NOXTLS_SECURE_FREE(server_key_exchange, 1024U + 320U + 512U); } else if (ctx->handshake_workspace != NULL) { noxtls_secure_zero((ctx->handshake_workspace), (size_t)(TLS_HANDSHAKE_WORKSPACE_SIZE)); }
                else {
                    /* MISRA 15.7: no remaining alternative */
                }
    return rc;
}

/**
 * @brief TLS 1.2 client: receive ECDHE ServerKeyExchange, verify signature if present, compute shared secret.
 * @param[in,out] ctx TLS 1.2 client context.
 * @param[in,out] ecdhe_ctx ECDHE state matching server group; receives shared secret.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on parse/verify/ECDH errors.
 */
noxtls_return_t noxtls_tls12_ecdhe_recv_server_key_exchange(tls12_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx)
{
    tls_record_t record;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t offset = 0U;
    uint8_t curve_type = 0U;
    uint16_t named_curve = 0U;
    uint8_t public_key_len = 0U;
    ecc_point_t peer_public_key;
    
    if ((ctx == NULL) || (ecdhe_ctx == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    if (ctx->base.base.role != TLS_ROLE_CLIENT) {
        return NOXTLS_RETURN_FAILED;
    }
    
    rc = noxtls_tls_recv_record(&ctx->base.base, &record);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if ((record.length > 0U) && (record.data == NULL)) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if (record.type != TLS_RECORD_HANDSHAKE) {
        (void)noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    if (record.data[0] != TLS_HANDSHAKE_SERVER_KEY_EXCHANGE) {
        (void)noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    offset = 4U;  /* Skip handshake header */
    
    /* Curve type */
    if (offset >= record.length) {
        (void)noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    curve_type = record.data[offset];
    offset += 1U;
    
    if (curve_type != TLS_EC_CURVE_TYPE_NAMED) {  /* Must be named_curve */
        (void)noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Named curve */
    if ((offset + 2U) > record.length) {
        (void)noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    named_curve = (uint16_t)(((uint16_t)record.data[offset] << 8U) | (uint16_t)record.data[offset + 1U]);
    offset += 2U;
    
    /* Verify named curve matches */
    if (named_curve != ecdhe_ctx->named_group) {
        (void)noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Public key length */
    if (offset >= record.length) {
        (void)noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    public_key_len = record.data[offset];
    offset += 1U;
    
    /* Public key */
    if(((offset + public_key_len) > record.length)) {
        (void)noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    if (ecdhe_ctx->named_group == TLS_NAMED_GROUP_X25519) {
        if (public_key_len != NOXTLS_X25519_KEY_SIZE) {
            (void)noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_tls_ecdhe_compute_shared_secret_x25519(ecdhe_ctx, &record.data[offset]);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(record.data);
            return rc;
        }
        offset += public_key_len;
    } else if (ecdhe_ctx->named_group == TLS_NAMED_GROUP_X448) {
        if (public_key_len != 56U) {
            (void)noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_tls_ecdhe_compute_shared_secret_x448(ecdhe_ctx, &record.data[offset]);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(record.data);
            return rc;
        }
        offset += public_key_len;
    } else {
    /* Decode peer's public key */
    rc = noxtls_tls_decode_ecc_point_uncompressed(&record.data[offset], public_key_len, &peer_public_key, ecdhe_ctx->curve_type);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(record.data);
        return rc;
    }
    offset += public_key_len;
    }
    uint32_t params_end = (uint32_t)(offset);  /* params = record.data[4..params_end-1] */

    /* Signature algorithm (2 bytes) and signature length (2 bytes) */
    if ((offset + 4U) > record.length) {
        (void)noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    {
        uint16_t sig_len = (uint16_t)(((uint16_t)record.data[offset + 2U] << 8U) | (uint16_t)record.data[offset + 3U]);
        offset += 4U;
        if ((sig_len == 0U) || ((offset + sig_len) > record.length)) {
            (void)noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        if (ctx->server_cert_parsed == NULL) {
            (void)noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        /*
         * Same verifier as the noxtls_tls12_recv_server_key_exchange() ECDHE path: honours the
         * SignatureAndHashAlgorithm (RSA PKCS#1 v1.5, RSA-PSS rsae, ECDSA), requires it to be
         * one the client offered and normalizes the certificate RSA modulus/exponent.
         */
        rc = noxtls_tls12_client_verify_ske_signature(ctx, record.data, record.length, params_end);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(record.data);
            if ((rc == NOXTLS_RETURN_NOT_ENOUGH_MEMORY) || (rc == NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER)) {
                return rc;
            }
            return NOXTLS_RETURN_FAILED;
        }
    }

    /* NIST curves: shared secret after signature verify. X25519/X448 already computed. */
    if ((ecdhe_ctx->named_group != TLS_NAMED_GROUP_X25519) &&
       (ecdhe_ctx->named_group != TLS_NAMED_GROUP_X448)) {
        rc = noxtls_tls_ecdhe_compute_shared_secret(ecdhe_ctx, &peer_public_key);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(record.data);
            return rc;
        }
    }
    
    (void)noxtls_free(record.data);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 client: send ClientKeyExchange with local ECDHE public key.
 * @param[in,out] ctx TLS 1.2 client context.
 * @param[in] ecdhe_ctx Local ECDHE public material.
 * @return `NOXTLS_RETURN_SUCCESS` if the record was sent; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on role or encode errors; `NOXTLS_RETURN_NOT_ENOUGH_MEMORY` on allocation failure.
 */
noxtls_return_t noxtls_tls12_ecdhe_send_client_key_exchange(tls12_context_t *ctx, const tls_ecdhe_context_t *ecdhe_ctx)
{
    if ((ctx == NULL) || (ecdhe_ctx == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (ctx->base.base.role != TLS_ROLE_CLIENT) {
        return NOXTLS_RETURN_FAILED;
    }
    uint8_t *client_key_exchange = ctx->handshake_workspace;
    if (client_key_exchange == NULL) {
        client_key_exchange = (uint8_t*)NOXTLS_MALLOC(512);
        if (client_key_exchange == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    uint32_t offset = 0U;
    uint8_t public_key_encoded[133];  /* Max: 1 + 2*66 for P-521 */
    uint32_t public_key_len = (uint32_t)sizeof(public_key_encoded);
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    /* Build Client Key Exchange noxtls_message */
    client_key_exchange[offset] = TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE;
    offset += 1U;
    client_key_exchange[offset] = 0x00U;
    offset += 1U;  /* Length (3 bytes) - placeholder */
    client_key_exchange[offset] = 0x00U;
    offset += 1U;
    client_key_exchange[offset] = 0x00U;
    offset += 1U;
    
    /* Get encoded public key */
    rc = noxtls_tls_ecdhe_get_public_key_encoded(ecdhe_ctx, public_key_encoded, &public_key_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        if (client_key_exchange != ctx->handshake_workspace) { NOXTLS_SECURE_FREE(client_key_exchange, 512); } else if (ctx->handshake_workspace != NULL) { noxtls_secure_zero((ctx->handshake_workspace), (size_t)(TLS_HANDSHAKE_WORKSPACE_SIZE)); }
                else {
                    /* MISRA 15.7: no remaining alternative */
                }
        return rc;
    }
    
    /* Public key length */
    client_key_exchange[offset] = (uint8_t)(public_key_len & 0xFFU);
    offset += 1U;
    
    /* Public key */
    noxtls_copy_u8(&client_key_exchange[offset], (size_t)(512), public_key_encoded, (size_t)(public_key_len));
    offset += public_key_len;
    
    /* Update handshake noxtls_message length */
    uint32_t handshake_len = (uint32_t)(offset - 4U);
    client_key_exchange[1] = (uint8_t)((handshake_len >>16U) & 0xFFU);
    client_key_exchange[2] = (uint8_t)((handshake_len >>8U) & 0xFFU);
    client_key_exchange[3] = (uint8_t)(handshake_len & 0xFFU);
    
    /* Send via record layer */
    rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, client_key_exchange, offset);
    if (client_key_exchange != ctx->handshake_workspace) { NOXTLS_SECURE_FREE(client_key_exchange, 512); } else if (ctx->handshake_workspace != NULL) { noxtls_secure_zero((ctx->handshake_workspace), (size_t)(TLS_HANDSHAKE_WORKSPACE_SIZE)); }
            else {
                /* MISRA 15.7: no remaining alternative */
            }
    return rc;
}

/**
 * @brief TLS 1.2 server: receive ClientKeyExchange and compute ECDHE shared secret.
 * @param[in,out] ctx TLS 1.2 server context.
 * @param[in,out] ecdhe_ctx Server ECDHE state; receives shared secret.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on parse or ECDH errors.
 */
noxtls_return_t noxtls_tls12_ecdhe_recv_client_key_exchange(tls12_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx)
{
    tls_record_t record;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t offset = 0U;
    uint8_t public_key_len = 0U;
    ecc_point_t peer_public_key;
    
    if ((ctx == NULL) || (ecdhe_ctx == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    if (ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    rc = noxtls_tls_recv_record(&ctx->base.base, &record);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if ((record.length > 0U) && (record.data == NULL)) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if (record.type != TLS_RECORD_HANDSHAKE) {
        (void)noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    if (record.data[0] != TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE) {
        (void)noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    offset = 4U;  /* Skip handshake header */
    
    /* Public key length */
    if (offset >= record.length) {
        (void)noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    public_key_len = record.data[offset];
    offset += 1U;
    
    /* Public key */
    if(((offset + public_key_len) > record.length)) {
        (void)noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    if (ecdhe_ctx->named_group == TLS_NAMED_GROUP_X25519) {
        if (public_key_len != NOXTLS_X25519_KEY_SIZE) {
            (void)noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_tls_ecdhe_compute_shared_secret_x25519(ecdhe_ctx, &record.data[offset]);
        (void)noxtls_free(record.data);
        return rc;
    }
    if (ecdhe_ctx->named_group == TLS_NAMED_GROUP_X448) {
        /* RFC 8422 §5.7 / RFC 7748: raw 56-byte X448 public value; all-zero secret rejected. */
        if (public_key_len != NOXTLS_X448_KEY_SIZE) {
            (void)noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_tls_ecdhe_compute_shared_secret_x448(ecdhe_ctx, &record.data[offset]);
        (void)noxtls_free(record.data);
        return rc;
    }

    /* Decode peer's public key */
    rc = noxtls_tls_decode_ecc_point_uncompressed(&record.data[offset], public_key_len, &peer_public_key, ecdhe_ctx->curve_type);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(record.data);
        return rc;
    }
    
    /* Compute shared secret */
    rc = noxtls_tls_ecdhe_compute_shared_secret(ecdhe_ctx, &peer_public_key);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(record.data);
        return rc;
    }
    
    (void)noxtls_free(record.data);
    
    return NOXTLS_RETURN_SUCCESS;
}

/* ========== TLS 1.2 DHE (FFDHE) ========== */

/**
 * @brief Initialize DHE context buffers for an RFC 7919 FFDHE named group.
 * @param[out] ctx Zeroed context; allocates limb buffers sized to the group prime.
 * @param[in] named_group FFDHE TLS code point.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p ctx is NULL; `NOXTLS_RETURN_FAILED` on unknown group or allocation failure.
 */
noxtls_return_t noxtls_tls_dhe_context_init(tls_dhe_context_t *ctx, uint16_t named_group)
{
#if NOXTLS_FEATURE_DH
    const uint8_t *p = NULL;
    const uint8_t *g = NULL;
    uint32_t p_len = 0U;

    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_secure_zero((ctx), sizeof(tls_dhe_context_t));
    if (noxtls_dh_ffdhe_params(named_group, &p, &g, &p_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    ctx->named_group = named_group;
    ctx->p_len = p_len;
    ctx->server_private = (uint8_t*)NOXTLS_MALLOC(p_len);
    ctx->server_public  = (uint8_t*)NOXTLS_MALLOC(p_len);
    ctx->client_private = (uint8_t*)NOXTLS_MALLOC(p_len);
    ctx->client_public  = (uint8_t*)NOXTLS_MALLOC(p_len);
    if ((ctx->server_private == NULL) || (ctx->server_public == NULL) ||
       (ctx->client_private == NULL) || (ctx->client_public == NULL)) {
        if (ctx->server_private != NULL) { (void)noxtls_free(ctx->server_private); }
        if (ctx->server_public != NULL) {  (void)noxtls_free(ctx->server_public); }
        if (ctx->client_private != NULL) { (void)noxtls_free(ctx->client_private); }
        if (ctx->client_public != NULL) {  (void)noxtls_free(ctx->client_public); }
        noxtls_secure_zero((ctx), sizeof(tls_dhe_context_t));
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
#else
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_secure_zero((ctx), sizeof(tls_dhe_context_t));
    (void)named_group;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

/**
 * @brief Free DHE limb buffers and reset context fields.
 * @param[in,out] ctx Context to release.
 * @return `NOXTLS_RETURN_SUCCESS`; `NOXTLS_RETURN_NULL` if @p ctx is NULL.
 */
noxtls_return_t noxtls_tls_dhe_context_free(tls_dhe_context_t *ctx)
{
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if (ctx->server_private != NULL) { (void)noxtls_free(ctx->server_private); ctx->server_private = NULL; }
    if (ctx->server_public != NULL)  { (void)noxtls_free(ctx->server_public);  ctx->server_public = NULL; }
    if (ctx->client_private != NULL) { (void)noxtls_free(ctx->client_private); ctx->client_private = NULL; }
    if (ctx->client_public != NULL)  { (void)noxtls_free(ctx->client_public);  ctx->client_public = NULL; }
    ctx->p_len = 0U;
    ctx->premaster_secret_len = 0U;
    return NOXTLS_RETURN_SUCCESS;
}

/* TLS 1.2: rsa sign (PKCS#1) in SignatureAndHashAlgorithm (RFC 5246). */
#define TLS12_SIG_SCHEME_RSA_PKCS1 0x01U

/**
 * @brief Select RSA PKCS#1 (0x01u) hash for TLS 1.2 ServerKeyExchange signing per RFC 5246.
 * @param[in] ctx TLS 1.2 context (reads client `signature_algorithms` when present).
 * @param[out] hash_byte_out SignatureAndHashAlgorithm hash byte for the wire.
 * @param[out] hash_out Library hash id used with `noxtls_rsa_sign`.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_NOT_SUPPORTED` if no acceptable RSA pair is advertised.
 */
noxtls_return_t noxtls_tls12_pick_rsa_pkcs1_skx_sig_hash(const tls12_context_t *ctx,
                                                         uint8_t *hash_byte_out,
                                                         noxtls_hash_algos_t *hash_out)
{
    const tls_signature_algorithms_extension_t *sa;

    if ((ctx == NULL) || (hash_byte_out == NULL) || (hash_out == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    sa = ctx->client_extensions.signature_algorithms;
    if ((sa != NULL) && (sa->algorithms != NULL) && (sa->count > 0U)) {
        uint32_t i = 0U;
        for (i = 0U; i < sa->count; i += 1U) {
            uint16_t pair = (uint16_t)(sa->algorithms[i]);
            uint8_t hb = (uint8_t)((((uint32_t)(pair) >>8U)) & 0xFFU);
            uint8_t sb = (uint8_t)(pair & 0xFFU);

            if (sb != TLS12_SIG_SCHEME_RSA_PKCS1) {
                continue;
            }
            switch (hb) {
#if NOXTLS_FEATURE_SHA1
            case 2U:
                *hash_byte_out = 2U;
                *hash_out = NOXTLS_HASH_SHA1;
                return NOXTLS_RETURN_SUCCESS;
#endif
#if NOXTLS_FEATURE_SHA224
            case 3U:
                *hash_byte_out = 3U;
                *hash_out = NOXTLS_HASH_SHA_224;
                return NOXTLS_RETURN_SUCCESS;
#endif
            case 4U:
                *hash_byte_out = 4U;
                *hash_out = NOXTLS_HASH_SHA_256;
                return NOXTLS_RETURN_SUCCESS;
#if NOXTLS_FEATURE_SHA384
            case 5U:
                *hash_byte_out = 5U;
                *hash_out = NOXTLS_HASH_SHA_384;
                return NOXTLS_RETURN_SUCCESS;
#endif
#if NOXTLS_FEATURE_SHA512
            case 6U:
                *hash_byte_out = 6U;
                *hash_out = NOXTLS_HASH_SHA_512;
                return NOXTLS_RETURN_SUCCESS;
#endif
            default:
                /* Intentional: no additional handling. */
                (void)0;
                break;
            }
        }
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    /*
     * No signature_algorithms extension (RFC 5246): tlslite/tlsfuzzer default SKE verify
     * list is rsa_pkcs1_sha1 only (hash=2, sig=1).
     */
#if NOXTLS_FEATURE_SHA1
    *hash_byte_out = 2U;
    *hash_out = NOXTLS_HASH_SHA1;
    return NOXTLS_RETURN_SUCCESS;
#else
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

/**
 * @brief Check if the X.509 certificate is RSASSA-PSS
 *
 * @param[in] cert The certificate to check
 * @return 1 if the certificate is RSASSA-PSS, 0 otherwise
 */
static int tls12_x509_spki_oid_is_rsassa_pss(const x509_certificate_t *cert)
{
    static const uint8_t rsassa_pss_oid[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x01U, 0x0AU };
    if (cert == NULL) {
        return 0;
    }
    if(cert->public_key_algorithm_oid_len == (uint32_t)sizeof(rsassa_pss_oid)) {
        if(noxtls_ct_equal(cert->public_key_algorithm_oid, rsassa_pss_oid, sizeof(rsassa_pss_oid)) != 0) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Convert the RSA wire scheme to the hash algorithm
 *
 * @param[in] wire The RSA wire scheme
 * @return The hash algorithm
 */
static noxtls_hash_algos_t tls12_rsa_wire_scheme_to_hash(uint16_t wire)
{
    switch (wire) {
    case 0x0201U:
        return NOXTLS_HASH_SHA1;
    case 0x0301U:
        return NOXTLS_HASH_SHA_224;
    case 0x0401U:
    case 0x0804U:
    case 0x0809U:
        return NOXTLS_HASH_SHA_256;
    case 0x0501U:
    case 0x0805U:
    case 0x080AU:
        return NOXTLS_HASH_SHA_384;
    case 0x0601U:
    case 0x0806U:
    case 0x080BU:
        return NOXTLS_HASH_SHA_512;
    default:
        return NOXTLS_HASH_SHA_256;
    }
}

/**
 * @brief Check if the server has an RSA signing key
 *
 * @param[in] ctx The TLS 1.2 context
 * @return 1 if the server has an RSA signing key, 0 otherwise
 */
static int tls12_server_has_rsa_signing_key(const tls12_context_t *ctx)
{
    if (ctx->server_private_rsa != NULL) {
        return 1;
    }
    if ((ctx->crypto_provider != NULL) && (ctx->crypto_provider->ops != NULL) &&
       (ctx->crypto_provider->ops->rsa_sign != NULL) && (ctx->server_private_key_handle != NULL)) {
        return 1;
    }
    return 0;
}

/**
 * @brief Prepare the RSA server key exchange scheme
 *
 * @param[in] ctx The TLS 1.2 context
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, or NOXTLS_RETURN_FAILED if the context is not a server
 */
noxtls_return_t noxtls_tls12_prepare_rsa_server_key_exchange_scheme(tls12_context_t *ctx)
{
    const tls_signature_algorithms_extension_t *sa;
    const x509_certificate_t *leaf_parsed = NULL;
    uint32_t i = 0U;

    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if (ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }

    ctx->tls12_rsa_skx_scheme_prepared = 0U;
    ctx->tls12_rsa_skx_use_pss_leaf_identity = 0U;
    ctx->tls12_rsa_skx_sign_use_pss = 0U;
    ctx->tls12_rsa_skx_wire_scheme = 0U;
    ctx->tls12_rsa_skx_sign_hash = NOXTLS_HASH_SHA_256;

    leaf_parsed = (const x509_certificate_t *)ctx->server_cert_parsed;
    sa = ctx->client_extensions.signature_algorithms;
    if ((sa == NULL) || (sa->algorithms == NULL) || (sa->count == 0U)) {
#if NOXTLS_FEATURE_SHA1
        ctx->tls12_rsa_skx_wire_scheme = 0x0201U;
        ctx->tls12_rsa_skx_sign_hash = NOXTLS_HASH_SHA1;
        ctx->tls12_rsa_skx_sign_use_pss = 0U;
        ctx->tls12_rsa_skx_scheme_prepared = 1U;
        return NOXTLS_RETURN_SUCCESS;
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    }

    for (i = 0U; i < sa->count; i += 1U) {
        uint16_t pair = (uint16_t)(sa->algorithms[i]);
        uint8_t hb = (uint8_t)((((uint32_t)(pair) >>8U)) & 0xFFU);
        uint8_t sb = (uint8_t)(pair & 0xFFU);

        /* Never negotiate MD5 for TLS 1.2 SKX signatures (tlsfuzzer "MD5 first" probes). */
        if (pair == 0x0101U) {
            continue;
        }
#if NOXTLS_TLS_ALGORITHM_FILTER
        if (noxtls_tls_signature_scheme_is_available(pair) == 0) {
            continue;
        }
#endif

        /* rsa_pss_rsae_sha{256,384,512} */
        if ((pair == 0x0804U) || (pair == 0x0805U) || (pair == 0x0806U)) {
            int pkcs1_capable = ((tls12_server_has_rsa_signing_key(ctx) != 0) ? 1 : 0);
            if (leaf_parsed != NULL) {
                if (tls12_x509_spki_oid_is_rsassa_pss(leaf_parsed) != 0) {
                    pkcs1_capable = 0;
                }
            }
            if ((pkcs1_capable == 0) || (ctx->server_private_rsa == NULL)) {
                continue;
            }
            ctx->tls12_rsa_skx_wire_scheme = pair;
            ctx->tls12_rsa_skx_sign_hash = tls12_rsa_wire_scheme_to_hash(pair);
            ctx->tls12_rsa_skx_sign_use_pss = 1U;
            ctx->tls12_rsa_skx_use_pss_leaf_identity = 0U;
            ctx->tls12_rsa_skx_scheme_prepared = 1U;
            return NOXTLS_RETURN_SUCCESS;
        }

        /* rsa_pss_pss_sha{256,384,512} */
        if ((pair == 0x0809U) || (pair == 0x080AU) || (pair == 0x080BU)) {
            if ((ctx->server_rsa_pss_leaf_cert != NULL) && (ctx->server_rsa_pss_leaf_cert_len > 0U) &&
               (ctx->server_private_rsa_pss_leaf != NULL)) {
                ctx->tls12_rsa_skx_wire_scheme = pair;
                ctx->tls12_rsa_skx_sign_hash = tls12_rsa_wire_scheme_to_hash(pair);
                ctx->tls12_rsa_skx_sign_use_pss = 1U;
                ctx->tls12_rsa_skx_use_pss_leaf_identity = 1U;
                ctx->tls12_rsa_skx_scheme_prepared = 1U;
                return NOXTLS_RETURN_SUCCESS;
            }
            if (leaf_parsed != NULL) {
                if (tls12_x509_spki_oid_is_rsassa_pss(leaf_parsed) != 0) {
                    if (tls12_server_has_rsa_signing_key(ctx) != 0) {
                        if (ctx->server_private_rsa != NULL) {
                            ctx->tls12_rsa_skx_wire_scheme = pair;
                            ctx->tls12_rsa_skx_sign_hash = tls12_rsa_wire_scheme_to_hash(pair);
                            ctx->tls12_rsa_skx_sign_use_pss = 1U;
                            ctx->tls12_rsa_skx_use_pss_leaf_identity = 0U;
                            ctx->tls12_rsa_skx_scheme_prepared = 1U;
                            return NOXTLS_RETURN_SUCCESS;
                        }
                    }
                }
            }
            continue;
        }

        /* PKCS#1 v1.5 RSA (hash, rsa) */
        if (sb == TLS12_SIG_SCHEME_RSA_PKCS1) {
            if (tls12_server_has_rsa_signing_key(ctx) == 0) {
                continue;
            }
            if (leaf_parsed != NULL) {
                if (tls12_x509_spki_oid_is_rsassa_pss(leaf_parsed) != 0) {
                    continue;
                }
            }
            switch (hb) {
#if NOXTLS_FEATURE_SHA1
            case 2U:
                ctx->tls12_rsa_skx_wire_scheme = 0x0201U;
                ctx->tls12_rsa_skx_sign_hash = NOXTLS_HASH_SHA1;
                ctx->tls12_rsa_skx_sign_use_pss = 0U;
                ctx->tls12_rsa_skx_use_pss_leaf_identity = 0U;
                ctx->tls12_rsa_skx_scheme_prepared = 1U;
                return NOXTLS_RETURN_SUCCESS;
#endif
#if NOXTLS_FEATURE_SHA224
            case 3U:
                ctx->tls12_rsa_skx_wire_scheme = 0x0301U;
                ctx->tls12_rsa_skx_sign_hash = NOXTLS_HASH_SHA_224;
                ctx->tls12_rsa_skx_sign_use_pss = 0U;
                ctx->tls12_rsa_skx_use_pss_leaf_identity = 0U;
                ctx->tls12_rsa_skx_scheme_prepared = 1U;
                return NOXTLS_RETURN_SUCCESS;
#endif
            case 4U:
                ctx->tls12_rsa_skx_wire_scheme = 0x0401U;
                ctx->tls12_rsa_skx_sign_hash = NOXTLS_HASH_SHA_256;
                ctx->tls12_rsa_skx_sign_use_pss = 0U;
                ctx->tls12_rsa_skx_use_pss_leaf_identity = 0U;
                ctx->tls12_rsa_skx_scheme_prepared = 1U;
                return NOXTLS_RETURN_SUCCESS;
#if NOXTLS_FEATURE_SHA384
            case 5U:
                ctx->tls12_rsa_skx_wire_scheme = 0x0501U;
                ctx->tls12_rsa_skx_sign_hash = NOXTLS_HASH_SHA_384;
                ctx->tls12_rsa_skx_sign_use_pss = 0U;
                ctx->tls12_rsa_skx_use_pss_leaf_identity = 0U;
                ctx->tls12_rsa_skx_scheme_prepared = 1U;
                return NOXTLS_RETURN_SUCCESS;
#endif
#if NOXTLS_FEATURE_SHA512
            case 6U:
                ctx->tls12_rsa_skx_wire_scheme = 0x0601U;
                ctx->tls12_rsa_skx_sign_hash = NOXTLS_HASH_SHA_512;
                ctx->tls12_rsa_skx_sign_use_pss = 0U;
                ctx->tls12_rsa_skx_use_pss_leaf_identity = 0U;
                ctx->tls12_rsa_skx_scheme_prepared = 1U;
                return NOXTLS_RETURN_SUCCESS;
#endif
            default:
                /* Intentional: no additional handling. */
                (void)0;
                break;
            }
        }
    }

    return NOXTLS_RETURN_NOT_SUPPORTED;
}

#define TLS12_SIG_SCHEME_ECDSA 0x03U

/**
 * @brief Return whether @p sigalg is an ECDSA SignatureAndHashAlgorithm pair supported for SKX.
 * @param[in] sigalg Combined hash (high byte) and signature (low byte) scheme.
 * @return 1 if supported, 0 otherwise.
 */
static int tls12_skx_ecdsa_sigalg_supported(uint16_t sigalg)
{
    static const uint16_t supported[] = {
        0x0603U, 0x0503U, 0x0403U, 0x0303U, 0x0203U,
    };
    uint32_t i = 0U;
    for (i = 0U; i < (uint32_t)(sizeof(supported) / sizeof(supported[0])); i += 1U) {
        if (supported[i] == sigalg) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Select ECDSA (0x03u) hash for TLS 1.2 ServerKeyExchange signing per RFC 5246.
 * @param[in] ctx TLS 1.2 context (reads client `signature_algorithms` when present).
 * @param[out] hash_byte_out SignatureAndHashAlgorithm hash byte for the wire.
 * @param[out] hash_out Library hash id for ECDSA signing.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_NOT_SUPPORTED` if no acceptable ECDSA pair is advertised.
 */
noxtls_return_t noxtls_tls12_pick_ecdsa_skx_sig_hash(const tls12_context_t *ctx,
                                                    uint8_t *hash_byte_out,
                                                    noxtls_hash_algos_t *hash_out)
{
    const tls_signature_algorithms_extension_t *sa;

    if ((ctx == NULL) || (hash_byte_out == NULL) || (hash_out == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    sa = ctx->client_extensions.signature_algorithms;
    if ((sa != NULL) && (sa->algorithms != NULL) && (sa->count > 0U)) {
        uint32_t i = 0U;
        for (i = 0U; i < sa->count; i += 1U) {
            uint16_t pair = (uint16_t)(sa->algorithms[i]);
            uint8_t hb = (uint8_t)((((uint32_t)(pair) >>8U)) & 0xFFU);
            uint8_t sb = (uint8_t)(pair & 0xFFU);

            if (sb != TLS12_SIG_SCHEME_ECDSA) {
                continue;
            }
            if (tls12_skx_ecdsa_sigalg_supported(pair) == 0) {
                continue;
            }
            switch (hb) {
#if NOXTLS_FEATURE_SHA1
            case 2U:
                *hash_byte_out = 2U;
                *hash_out = NOXTLS_HASH_SHA1;
                return NOXTLS_RETURN_SUCCESS;
#endif
#if NOXTLS_FEATURE_SHA224
            case 3U:
                *hash_byte_out = 3U;
                *hash_out = NOXTLS_HASH_SHA_224;
                return NOXTLS_RETURN_SUCCESS;
#endif
            case 4U:
                *hash_byte_out = 4U;
                *hash_out = NOXTLS_HASH_SHA_256;
                return NOXTLS_RETURN_SUCCESS;
#if NOXTLS_FEATURE_SHA384
            case 5U:
                *hash_byte_out = 5U;
                *hash_out = NOXTLS_HASH_SHA_384;
                return NOXTLS_RETURN_SUCCESS;
#endif
#if NOXTLS_FEATURE_SHA512
            case 6U:
                *hash_byte_out = 6U;
                *hash_out = NOXTLS_HASH_SHA_512;
                return NOXTLS_RETURN_SUCCESS;
#endif
            default:
                /* Intentional: no additional handling. */
                (void)0;
                break;
            }
        }
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    if (ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA) {
#if NOXTLS_FEATURE_SHA1
        *hash_byte_out = 2U;
        *hash_out = NOXTLS_HASH_SHA1;
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else if (ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384) {
#if NOXTLS_FEATURE_SHA384
        *hash_byte_out = 5U;
        *hash_out = NOXTLS_HASH_SHA_384;
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else {
        /* MISRA 15.7: final else path */
        *hash_byte_out = 4U;
        *hash_out = NOXTLS_HASH_SHA_256;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 server: build and send DHE ServerKeyExchange (optional RSA signature); optionally copy message for transcript.
 * @param[in,out] ctx TLS 1.2 server context.
 * @param[in,out] dhe_ctx FFDHE context; server DH key generated here.
 * @param[out] msg_out Optional buffer to receive a copy of the handshake message.
 * @param[in] msg_out_size Size of @p msg_out when used.
 * @param[out] msg_out_len Written length when @p msg_out and @p msg_out_len are non-NULL and buffer is large enough.
 * @return `NOXTLS_RETURN_SUCCESS` if the record was sent; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on build/sign errors; `NOXTLS_RETURN_NOT_ENOUGH_MEMORY` on allocation failure.
 */
noxtls_return_t noxtls_tls12_dhe_send_server_key_exchange(tls12_context_t *ctx, tls_dhe_context_t *dhe_ctx, uint8_t *msg_out, uint32_t msg_out_size, uint32_t *msg_out_len)
{
#if NOXTLS_FEATURE_DH
    const uint8_t *p = NULL;
    const uint8_t *g = NULL;
    uint32_t p_len = 0U;
    uint8_t *server_key_exchange = NULL;
    uint8_t *to_sign = NULL;
    uint8_t *sig_buf = NULL;
    uint8_t *alloc_aux = NULL;  /* when workspace used: &to_sign[sig_buf] block */
    uint32_t offset = 0U;
    uint32_t params_start = 0U;
    uint32_t params_len = 0U;
    uint32_t sig_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((ctx == NULL) || (dhe_ctx == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    if (noxtls_dh_ffdhe_params(dhe_ctx->named_group, &p, &g, &p_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if (p_len != dhe_ctx->p_len) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = noxtls_dh_generate_key(p, p_len, g, p_len, dhe_ctx->server_private, dhe_ctx->server_public);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if (ctx->handshake_workspace != NULL) {
        server_key_exchange = ctx->handshake_workspace;
        alloc_aux = (uint8_t*)NOXTLS_MALLOC(DHE_TO_SIGN_SIZE + DHE_SIG_BUF_SIZE);
        if (alloc_aux == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        to_sign = alloc_aux;
        sig_buf = &alloc_aux[DHE_TO_SIGN_SIZE];
    } else {
        /* MISRA 15.7: final else path */
        server_key_exchange = (uint8_t*)NOXTLS_MALLOC(NOXTLS_TLS12_DHE_SKX_MSG_MAX + DHE_TO_SIGN_SIZE + DHE_SIG_BUF_SIZE);
        if (server_key_exchange == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        to_sign = &server_key_exchange[NOXTLS_TLS12_DHE_SKX_MSG_MAX];
        sig_buf = &server_key_exchange[NOXTLS_TLS12_DHE_SKX_MSG_MAX + DHE_TO_SIGN_SIZE];
    }

    server_key_exchange[offset] = TLS_HANDSHAKE_SERVER_KEY_EXCHANGE;

    offset += 1U;
    server_key_exchange[offset] = 0x00U;
    offset += 1U;
    server_key_exchange[offset] = 0x00U;
    offset += 1U;
    server_key_exchange[offset] = 0x00U;
    offset += 1U;
    params_start = offset;

    /* dh_p: 2-byte length + p */
    server_key_exchange[offset] = (uint8_t)((p_len >>8U) & 0xFFU);
    offset += 1U;
    server_key_exchange[offset] = (uint8_t)(p_len & 0xFFU);
    offset += 1U;
    noxtls_copy_u8(&server_key_exchange[offset], (size_t)(NOXTLS_TLS12_DHE_SKX_MSG_MAX + DHE_TO_SIGN_SIZE + DHE_SIG_BUF_SIZE), p, (size_t)(p_len));
    offset += p_len;
    /* dh_g: 2-byte length + g */
    server_key_exchange[offset] = (uint8_t)((p_len >>8U) & 0xFFU);
    offset += 1U;
    server_key_exchange[offset] = (uint8_t)(p_len & 0xFFU);
    offset += 1U;
    noxtls_copy_u8(&server_key_exchange[offset], (size_t)(NOXTLS_TLS12_DHE_SKX_MSG_MAX + DHE_TO_SIGN_SIZE + DHE_SIG_BUF_SIZE), g, (size_t)(p_len));
    offset += p_len;
    /* dh_Ys: 2-byte length + Ys */
    server_key_exchange[offset] = (uint8_t)((p_len >>8U) & 0xFFU);
    offset += 1U;
    server_key_exchange[offset] = (uint8_t)(p_len & 0xFFU);
    offset += 1U;
    noxtls_copy_u8(&server_key_exchange[offset], (size_t)(NOXTLS_TLS12_DHE_SKX_MSG_MAX + DHE_TO_SIGN_SIZE + DHE_SIG_BUF_SIZE), dhe_ctx->server_public, (size_t)(p_len));
    offset += p_len;
    params_len = offset - params_start;

    {
        uint8_t dhe_sig_hi = 0U;
        uint8_t dhe_sig_lo = 0U;
        noxtls_hash_algos_t dhe_ske_sign_hash = NOXTLS_HASH_SHA_256;

        if (ctx->tls12_rsa_skx_scheme_prepared != 0U) {
            dhe_sig_hi = (uint8_t)((((uint32_t)ctx->tls12_rsa_skx_wire_scheme) >> 8U) & 0xFFU);
            dhe_sig_lo = (uint8_t)(ctx->tls12_rsa_skx_wire_scheme & 0xFFU);
            dhe_ske_sign_hash = ctx->tls12_rsa_skx_sign_hash;
        } else {
            uint8_t dhe_ske_hash_byte = 0U;
            rc = noxtls_tls12_pick_rsa_pkcs1_skx_sig_hash(ctx, &dhe_ske_hash_byte, &dhe_ske_sign_hash);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                if (alloc_aux != NULL) { NOXTLS_SECURE_FREE(alloc_aux, DHE_TO_SIGN_SIZE + DHE_SIG_BUF_SIZE); }
                if (server_key_exchange != ctx->handshake_workspace) {
                    NOXTLS_SECURE_FREE(server_key_exchange, NOXTLS_TLS12_DHE_SKX_MSG_MAX + DHE_TO_SIGN_SIZE + DHE_SIG_BUF_SIZE);
                } else if (ctx->handshake_workspace != NULL) {
                    noxtls_secure_zero((ctx->handshake_workspace), (size_t)(TLS_HANDSHAKE_WORKSPACE_SIZE));
                }
                 else {
                     /* MISRA 15.7: no remaining alternative */
                 }
                return rc;
            }
            dhe_sig_hi = dhe_ske_hash_byte;
            dhe_sig_lo = 0x01U;
        }

    if ((ctx->crypto_provider != NULL) && (ctx->crypto_provider->ops != NULL) && (ctx->crypto_provider->ops->rsa_sign != NULL) && (ctx->server_private_key_handle != NULL) &&
       (params_len <= (DHE_TO_SIGN_SIZE - (TLS_RANDOM_SIZE * 2U))) &&
       ((ctx->tls12_rsa_skx_scheme_prepared == 0U) || (ctx->tls12_rsa_skx_sign_use_pss == 0U))) {
        noxtls_copy_u8(to_sign, (size_t)DHE_TO_SIGN_SIZE, ctx->client_random, (size_t)(TLS_RANDOM_SIZE));
        noxtls_copy_u8(&to_sign[TLS_RANDOM_SIZE], (size_t)DHE_TO_SIGN_SIZE - (size_t)(TLS_RANDOM_SIZE), ctx->server_random, (size_t)(TLS_RANDOM_SIZE));
        noxtls_copy_u8(&to_sign[((size_t)TLS_RANDOM_SIZE * 2U)], (size_t)DHE_TO_SIGN_SIZE - (size_t)(((size_t)TLS_RANDOM_SIZE * 2U)), &server_key_exchange[params_start], (size_t)(params_len));
        uint32_t to_sign_len = (uint32_t)(TLS_RANDOM_SIZE + TLS_RANDOM_SIZE + params_len);
        sig_len = DHE_SIG_BUF_SIZE;
        rc = ctx->crypto_provider->ops->rsa_sign(ctx->crypto_provider->ctx, ctx->server_private_key_handle,
                to_sign, to_sign_len, sig_buf, &sig_len, (noxtls_crypto_hash_algo_t)dhe_ske_sign_hash);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            if (alloc_aux != NULL) { NOXTLS_SECURE_FREE(alloc_aux, DHE_TO_SIGN_SIZE + DHE_SIG_BUF_SIZE); }
            if (server_key_exchange != ctx->handshake_workspace) {
                NOXTLS_SECURE_FREE(server_key_exchange, NOXTLS_TLS12_DHE_SKX_MSG_MAX + DHE_TO_SIGN_SIZE + DHE_SIG_BUF_SIZE);
            } else if (ctx->handshake_workspace != NULL) {
                noxtls_secure_zero((ctx->handshake_workspace), (size_t)(TLS_HANDSHAKE_WORKSPACE_SIZE));
            }
             else {
                 /* MISRA 15.7: no remaining alternative */
             }
            return rc;
        }
        server_key_exchange[offset] = dhe_sig_hi;
        offset += 1U;
        server_key_exchange[offset] = dhe_sig_lo;
        offset += 1U;
        server_key_exchange[offset] = (uint8_t)((sig_len >>8U) & 0xFFU);
        offset += 1U;
        server_key_exchange[offset] = (uint8_t)(sig_len & 0xFFU);
        offset += 1U;
        noxtls_copy_u8(&server_key_exchange[offset], (size_t)NOXTLS_TLS12_DHE_SKX_MSG_MAX - (size_t)(offset), sig_buf, (size_t)(sig_len));
        offset += sig_len;
    } else if ((ctx->server_private_rsa != NULL) && (params_len <= (DHE_TO_SIGN_SIZE - (TLS_RANDOM_SIZE * 2U)))) {
        const rsa_key_t *dhe_rsa_key = (const rsa_key_t *)ctx->server_private_rsa;
        if ((ctx->tls12_rsa_skx_scheme_prepared != 0U) && (ctx->tls12_rsa_skx_use_pss_leaf_identity != 0U) &&
           (ctx->server_private_rsa_pss_leaf != NULL)) {
            dhe_rsa_key = (const rsa_key_t *)ctx->server_private_rsa_pss_leaf;
        }
        noxtls_copy_u8(to_sign, (size_t)DHE_TO_SIGN_SIZE, ctx->client_random, (size_t)(TLS_RANDOM_SIZE));
        noxtls_copy_u8(&to_sign[TLS_RANDOM_SIZE], (size_t)DHE_TO_SIGN_SIZE - (size_t)(TLS_RANDOM_SIZE), ctx->server_random, (size_t)(TLS_RANDOM_SIZE));
        noxtls_copy_u8(&to_sign[((size_t)TLS_RANDOM_SIZE * 2U)], (size_t)DHE_TO_SIGN_SIZE - (size_t)(((size_t)TLS_RANDOM_SIZE * 2U)), &server_key_exchange[params_start], (size_t)(params_len));
        uint32_t to_sign_len = (uint32_t)(TLS_RANDOM_SIZE + TLS_RANDOM_SIZE + params_len);
        sig_len = DHE_SIG_BUF_SIZE;
#if NOXTLS_FEATURE_RSA
        if ((ctx->tls12_rsa_skx_scheme_prepared != 0U) && (ctx->tls12_rsa_skx_sign_use_pss != 0U)) {
            rc = noxtls_rsa_sign_pss(dhe_rsa_key, to_sign, to_sign_len, sig_buf, &sig_len, dhe_ske_sign_hash);
        } else {
            rc = noxtls_rsa_sign(dhe_rsa_key, to_sign, to_sign_len, sig_buf, &sig_len, dhe_ske_sign_hash);
        }
#else
        (void)dhe_rsa_key;
        (void)to_sign_len;
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        if (rc != NOXTLS_RETURN_SUCCESS) {
            if (alloc_aux != NULL) { NOXTLS_SECURE_FREE(alloc_aux, DHE_TO_SIGN_SIZE + DHE_SIG_BUF_SIZE); }
            if (server_key_exchange != ctx->handshake_workspace) {
                NOXTLS_SECURE_FREE(server_key_exchange, NOXTLS_TLS12_DHE_SKX_MSG_MAX + DHE_TO_SIGN_SIZE + DHE_SIG_BUF_SIZE);
            } else if (ctx->handshake_workspace != NULL) {
                noxtls_secure_zero((ctx->handshake_workspace), (size_t)(TLS_HANDSHAKE_WORKSPACE_SIZE));
            }
             else {
                 /* MISRA 15.7: no remaining alternative */
             }
            return rc;
        }
        server_key_exchange[offset] = dhe_sig_hi;
        offset += 1U;
        server_key_exchange[offset] = dhe_sig_lo;
        offset += 1U;
        server_key_exchange[offset] = (uint8_t)((sig_len >>8U) & 0xFFU);
        offset += 1U;
        server_key_exchange[offset] = (uint8_t)(sig_len & 0xFFU);
        offset += 1U;
        noxtls_copy_u8(&server_key_exchange[offset], (size_t)NOXTLS_TLS12_DHE_SKX_MSG_MAX - (size_t)(offset), sig_buf, (size_t)(sig_len));
        offset += sig_len;
    } else {
        server_key_exchange[offset] = 0x00U;
        offset += 1U;
        server_key_exchange[offset] = 0x00U;
        offset += 1U;
        server_key_exchange[offset] = 0x00U;
        offset += 1U;
        server_key_exchange[offset] = 0x00U;
        offset += 1U;
    }
    }

    params_len = offset - 4U;
    server_key_exchange[1] = (uint8_t)((params_len >>16U) & 0xFFU);
    server_key_exchange[2] = (uint8_t)((params_len >>8U) & 0xFFU);
    server_key_exchange[3] = (uint8_t)(params_len & 0xFFU);
    if ((msg_out != NULL) && (msg_out_len != NULL) && (msg_out_size >= offset)) {
        noxtls_copy_u8(msg_out, (size_t)offset, server_key_exchange, (size_t)offset);
        *msg_out_len = offset;
    }
    rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, server_key_exchange, offset);
    if (alloc_aux != NULL) { NOXTLS_SECURE_FREE(alloc_aux, DHE_TO_SIGN_SIZE + DHE_SIG_BUF_SIZE); }
    if (server_key_exchange != ctx->handshake_workspace) {
        NOXTLS_SECURE_FREE(server_key_exchange, NOXTLS_TLS12_DHE_SKX_MSG_MAX + DHE_TO_SIGN_SIZE + DHE_SIG_BUF_SIZE);
    }
    return rc;
#else
    (void)ctx;
    (void)dhe_ctx;
    (void)msg_out;
    (void)msg_out_size;
    (void)msg_out_len;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

#if NOXTLS_FEATURE_DH
/**
 * @brief Skip leading zero octets of a big-endian unsigned integer.
 * @param[in,out] v Pointer to the integer; advanced past leading zeros.
 * @param[in,out] len Length of the integer; reduced accordingly (0 for the value zero).
 */
static void tls_dhe_skip_leading_zeros(const uint8_t **v, uint32_t *len)
{
    while ((*len > 0U) && ((*v)[0] == 0x00U)) {
        *v = &(*v)[1];
        *len -= 1U;
    }
}

/**
 * @brief Check 1 < g < p - 1 for a minimal-length generator against an odd prime.
 * @param[in] g Generator without leading zero octets.
 * @param[in] g_len Length of @p g (0 means g == 0).
 * @param[in] p Odd prime without leading zero octets.
 * @param[in] p_len Length of @p p.
 * @return 1 if the generator is in range, 0 otherwise.
 */
static int tls_dhe_generator_in_range(const uint8_t *g, uint32_t g_len, const uint8_t *p, uint32_t p_len)
{
    uint32_t i = 0U;
    uint32_t pad = 0U;
    int cmp = 0;

    if ((g_len == 0U) || (p_len == 0U) || (g_len > p_len) || ((p[p_len - 1U] & 0x01U) == 0U)) {
        return 0;
    }
    if ((g_len == 1U) && (g[0] <= 1U)) {
        return 0;   /* g == 0 or g == 1 */
    }
    /* Compare g with p - 1 (p is odd, so p - 1 only clears the low bit; no borrow). */
    pad = p_len - g_len;
    for (i = 0U; (i < p_len) && (cmp == 0); i += 1U) {
        uint8_t gb = (i < pad) ? (uint8_t)0x00U : g[i - pad];
        uint8_t pb = (i == (p_len - 1U)) ? (uint8_t)(p[i] & 0xFEU) : p[i];
        if (gb < pb) {
            cmp = -1;
        } else if (gb > pb) {
            cmp = 1;
        } else {
            /* MISRA 15.7: equal octet, keep scanning */
        }
    }
    return (cmp < 0) ? 1 : 0;
}
#endif /* NOXTLS_FEATURE_DH */

/**
 * @brief TLS 1.2 client: parse DHE ServerKeyExchange from caller-supplied handshake bytes.
 *
 * The server's dh_p must be the RFC 7919 prime of @p dhe_ctx->named_group (leading zero
 * octets allowed). dh_g may use any encoding length (typically one octet) and must satisfy
 * 1 < g < p - 1. The signature is verified with the SignatureAndHashAlgorithm the server
 * used (RSA PKCS#1 v1.5 or RSA-PSS), which must be one the client offered.
 *
 * @param[in,out] ctx TLS 1.2 client context.
 * @param[in,out] dhe_ctx DHE context for expected group; receives server public and premaster.
 * @param[in] record_data Full handshake message including 4-byte header.
 * @param[in] record_len Length of @p record_data.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED`,
 *         `NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER` (scheme not offered) or `NOXTLS_RETURN_TLS_WEAK_DHE_PARAMS`
 *         on validation failure; `NOXTLS_RETURN_NOT_ENOUGH_MEMORY` on allocation failure.
 */
noxtls_return_t noxtls_tls12_dhe_recv_server_key_exchange(tls12_context_t *ctx, tls_dhe_context_t *dhe_ctx, const uint8_t *record_data, uint32_t record_len)
{
#if NOXTLS_FEATURE_DH
    const uint8_t *p = NULL;
    const uint8_t *g = NULL;
    const uint8_t *srv_p = NULL;
    const uint8_t *srv_g = NULL;
    const uint8_t *exp_p = NULL;
    uint32_t p_len = 0U;
    uint32_t srv_p_len = 0U;
    uint32_t srv_g_len = 0U;
    uint32_t exp_p_len = 0U;
    uint32_t off = 0U;
    uint32_t params_end = 0U;
    uint16_t len_p = 0U;
    uint16_t len_g = 0U;
    uint16_t len_Ys = 0U;
    uint16_t sig_len = 0U;
    const uint8_t *ys_ptr = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((ctx == NULL) || (dhe_ctx == NULL) || (record_data == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (ctx->base.base.role != TLS_ROLE_CLIENT) {
        return NOXTLS_RETURN_FAILED;
    }
    if ((record_len < 4U) || (record_data[0] != TLS_HANDSHAKE_SERVER_KEY_EXCHANGE)) {
        return NOXTLS_RETURN_FAILED;
    }

    off = 4U;
    if ((off + 2U) > record_len) {
        return NOXTLS_RETURN_FAILED;
    }
    len_p = (uint16_t)(((uint16_t)record_data[off] << 8U) | (uint16_t)record_data[off + 1U]);
    off += 2U;
    if ((off + len_p + 2U) > record_len) {
        return NOXTLS_RETURN_FAILED;
    }
    srv_p = &record_data[off];
    off += len_p;
    len_g = (uint16_t)(((uint16_t)record_data[off] << 8U) | (uint16_t)record_data[off + 1U]);
    off += 2U;
    if ((off + len_g + 2U) > record_len) {
        return NOXTLS_RETURN_FAILED;
    }
    srv_g = &record_data[off];
    off += len_g;
    len_Ys = (uint16_t)(((uint16_t)record_data[off] << 8U) | (uint16_t)record_data[off + 1U]);
    off += 2U;
    if ((off + len_Ys) > record_len) {
        return NOXTLS_RETURN_FAILED;
    }
    if ((noxtls_dh_ffdhe_params(dhe_ctx->named_group, &p, &g, &p_len) != NOXTLS_RETURN_SUCCESS) ||
       (len_Ys == 0U) || (len_Ys > p_len) || (p_len > dhe_ctx->p_len)) {
        return NOXTLS_RETURN_TLS_WEAK_DHE_PARAMS;
    }
    (void)g;
    /*
     * dh_p must be the negotiated RFC 7919 prime. Compare as integers so a leading zero
     * octet (DER-style sign padding) is accepted.
     */
    srv_p_len = (uint32_t)len_p;
    tls_dhe_skip_leading_zeros(&srv_p, &srv_p_len);
    exp_p = p;
    exp_p_len = p_len;
    tls_dhe_skip_leading_zeros(&exp_p, &exp_p_len);
    if ((srv_p_len != exp_p_len) || (exp_p_len == 0U) ||
       (noxtls_ct_memcmp(srv_p, exp_p, (size_t)exp_p_len) != 0)) {
        return NOXTLS_RETURN_TLS_WEAK_DHE_PARAMS;
    }
    /* dh_g: minimal (usually 1-octet) or padded encoding; require 1 < g < p - 1. */
    srv_g_len = (uint32_t)len_g;
    tls_dhe_skip_leading_zeros(&srv_g, &srv_g_len);
    if (tls_dhe_generator_in_range(srv_g, srv_g_len, exp_p, exp_p_len) == 0) {
        return NOXTLS_RETURN_TLS_WEAK_DHE_PARAMS;
    }
    ys_ptr = &record_data[off];
    off += len_Ys;
    params_end = off;

    /* SignatureAndHashAlgorithm (2) + signature length (2) + signature, ending the message. */
    if ((off + 4U) > record_len) {
        return NOXTLS_RETURN_FAILED;
    }
    sig_len = (uint16_t)(((uint16_t)record_data[off + 2U] << 8U) | (uint16_t)record_data[off + 3U]);
    if ((sig_len == 0U) || ((off + 4U + (uint32_t)sig_len) != record_len) ||
       (ctx->server_cert_parsed == NULL)) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = noxtls_tls12_client_verify_ske_signature(ctx, record_data, record_len, params_end);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        if ((rc == NOXTLS_RETURN_NOT_ENOUGH_MEMORY) || (rc == NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER)) {
            return rc;
        }
        return NOXTLS_RETURN_FAILED;
    }

    noxtls_secure_zero((dhe_ctx->server_public), ((size_t)dhe_ctx->p_len));
    noxtls_copy_u8(&dhe_ctx->server_public[(p_len - len_Ys)], (size_t)len_Ys, ys_ptr, (size_t)len_Ys);

    rc = noxtls_dh_generate_key(p, p_len, srv_g, srv_g_len, dhe_ctx->client_private, dhe_ctx->client_public);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_dh_shared_secret(dhe_ctx->client_private, p_len, ys_ptr, len_Ys, p, p_len,
                                  dhe_ctx->premaster_secret);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    dhe_ctx->premaster_secret_len = p_len;
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)ctx;
    (void)dhe_ctx;
    (void)record_data;
    (void)record_len;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

/**
 * @brief TLS 1.2 client: send DHE ClientKeyExchange with local DH public value.
 * @param[in,out] ctx TLS 1.2 client context.
 * @param[in] dhe_ctx Client public must be valid for the negotiated prime size.
 * @return `NOXTLS_RETURN_SUCCESS` if the record was sent; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on role or size errors; `NOXTLS_RETURN_NOT_ENOUGH_MEMORY` on allocation failure.
 */
noxtls_return_t noxtls_tls12_dhe_send_client_key_exchange(tls12_context_t *ctx, const tls_dhe_context_t *dhe_ctx)
{
    if ((ctx == NULL) || (dhe_ctx == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (ctx->base.base.role != TLS_ROLE_CLIENT) {
        return NOXTLS_RETURN_FAILED;
    }
    uint8_t *client_key_exchange = ctx->handshake_workspace;
    if (client_key_exchange == NULL) {
        client_key_exchange = (uint8_t*)NOXTLS_MALLOC(1024);
        if (client_key_exchange == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    uint32_t offset = 0U;
    uint32_t p_len = (uint32_t)(dhe_ctx->p_len);

    if ((p_len + 6U) > 1024U) {
        if (client_key_exchange != ctx->handshake_workspace) { NOXTLS_SECURE_FREE(client_key_exchange, 1024); } else if (ctx->handshake_workspace != NULL) { noxtls_secure_zero((ctx->handshake_workspace), (size_t)(TLS_HANDSHAKE_WORKSPACE_SIZE)); }
                else {
                    /* MISRA 15.7: no remaining alternative */
                }
        return NOXTLS_RETURN_FAILED;
    }
    client_key_exchange[offset] = TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE;
    offset += 1U;
    client_key_exchange[offset] = 0x00U;
    offset += 1U;
    client_key_exchange[offset] = 0x00U;
    offset += 1U;
    client_key_exchange[offset] = 0x00U;
    offset += 1U;
    client_key_exchange[offset] = (uint8_t)((p_len >>8U) & 0xFFU);
    offset += 1U;
    client_key_exchange[offset] = (uint8_t)(p_len & 0xFFU);
    offset += 1U;
    noxtls_copy_u8(&client_key_exchange[offset], (size_t)(1024), dhe_ctx->client_public, (size_t)(p_len));
    offset += p_len;
    uint32_t handshake_len = (uint32_t)(offset - 4U);
    client_key_exchange[1] = (uint8_t)((handshake_len >>16U) & 0xFFU);
    client_key_exchange[2] = (uint8_t)((handshake_len >>8U) & 0xFFU);
    client_key_exchange[3] = (uint8_t)(handshake_len & 0xFFU);
    noxtls_return_t rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, client_key_exchange, offset);
    if (client_key_exchange != ctx->handshake_workspace) { NOXTLS_SECURE_FREE(client_key_exchange, 1024); } else if (ctx->handshake_workspace != NULL) { noxtls_secure_zero((ctx->handshake_workspace), (size_t)(TLS_HANDSHAKE_WORKSPACE_SIZE)); }
            else {
                /* MISRA 15.7: no remaining alternative */
            }
    return rc;
}

/**
 * @brief TLS 1.2 server: parse DHE ClientKeyExchange and derive premaster secret.
 * @param[in,out] ctx TLS 1.2 server context.
 * @param[in,out] dhe_ctx Server DHE state; receives premaster in `premaster_secret`.
 * @param[in] record_data Handshake message bytes including header.
 * @param[in] record_len Length of @p record_data.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; TLS alert codes on malformed messages.
 */
noxtls_return_t noxtls_tls12_dhe_recv_client_key_exchange(const tls12_context_t *ctx, tls_dhe_context_t *dhe_ctx, const uint8_t *record_data, uint32_t record_len)
{
#if NOXTLS_FEATURE_DH
    const uint8_t *p = NULL;
    const uint8_t *g = NULL;
    uint32_t p_len = 0U;
    uint32_t off = 0U;
    uint16_t len_Yc = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((ctx == NULL) || (dhe_ctx == NULL) || (record_data == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    if ((record_len < 6U) || (record_data[0] != TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE)) {
        (void)noxtls_debug_printf((const uint8_t *)"[TLS12_DHE] bad CKE header: len=%u type=%u\n",
                                  record_len, (record_len > 0U) ? record_data[0] : 0U);
        return NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
    }
    off = 4U;
    len_Yc = (uint16_t)(((uint16_t)record_data[off] << 8U) | (uint16_t)record_data[off + 1U]);
    off += 2U;
    if (len_Yc == 0U) {
        (void)noxtls_debug_printf((const uint8_t *)"[TLS12_DHE] zero-length dh_Yc (decode)\n");
        return NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
    }
    if (len_Yc > dhe_ctx->p_len) {
        (void)noxtls_debug_printf((const uint8_t *)"[TLS12_DHE] bad Yc length: len_Yc=%u record_len=%u p_len=%u\n",
                                   (uint32_t)len_Yc, (uint32_t)record_len, (uint32_t)dhe_ctx->p_len);
        return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
    }
    /* Body must be exactly 2 + len_Yc bytes (no trailing padding in ClientKeyExchange). */
    if ((6U + (uint32_t)len_Yc) != record_len) {
        (void)noxtls_debug_printf((const uint8_t *)"[TLS12_DHE] CKE length mismatch: len_Yc=%u record_len=%u (expected %u)\n",
                                  (uint32_t)len_Yc, (uint32_t)record_len, (uint32_t)(6U + (uint32_t)len_Yc));
        return NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
    }
    noxtls_secure_zero((dhe_ctx->client_public), ((size_t)dhe_ctx->p_len));
    noxtls_copy_u8(&dhe_ctx->client_public[(dhe_ctx->p_len - len_Yc)], (size_t)len_Yc, &record_data[off], (size_t)len_Yc);
    p_len = dhe_ctx->p_len;
    if (noxtls_dh_ffdhe_params(dhe_ctx->named_group, &p, &g, &p_len) != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_debug_printf((const uint8_t *)"[TLS12_DHE] failed to resolve FFDHE params for group=0x%04X\n",
                                  (uint32_t)dhe_ctx->named_group);
        return NOXTLS_RETURN_FAILED;
    }
    rc = noxtls_dh_shared_secret(dhe_ctx->server_private, p_len, &record_data[off], len_Yc, p, p_len,
                                  dhe_ctx->premaster_secret);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_debug_printf((const uint8_t *)"[TLS12_DHE] shared_secret failed: rc=%d len_Yc=%u p_len=%u\n",
                                  (int)rc, (uint32_t)len_Yc, (uint32_t)p_len);
        return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
    }
    dhe_ctx->premaster_secret_len = p_len;
    (void)noxtls_debug_printf((const uint8_t *)"[TLS12_DHE] CKE ok: Yc_len=%u premaster_len=%u premaster[0..3]=%02X%02X%02X%02X\n",
                              (uint32_t)len_Yc, (uint32_t)dhe_ctx->premaster_secret_len,
                              (dhe_ctx->premaster_secret_len > 0U) ? dhe_ctx->premaster_secret[0] : 0U,
                              (dhe_ctx->premaster_secret_len > 1U) ? dhe_ctx->premaster_secret[1] : 0U,
                              (dhe_ctx->premaster_secret_len > 2U) ? dhe_ctx->premaster_secret[2] : 0U,
                              (dhe_ctx->premaster_secret_len > 3U) ? dhe_ctx->premaster_secret[3] : 0U);
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)ctx;
    (void)dhe_ctx;
    (void)record_data;
    (void)record_len;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

/**
 * @brief TLS 1.3: encode one KeyShareEntry (group, length, key bytes).
 * @param[in] ecdhe_ctx Local share for one named group.
 * @param[out] output Serialized KeyShareEntry.
 * @param[in,out] output_len On input, size of @p output; on success, written length; if too small, set to required length.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` if encoding fails or buffer is too small.
 */
noxtls_return_t noxtls_tls13_key_share_encode(const tls_ecdhe_context_t *ecdhe_ctx, uint8_t *output, uint32_t *output_len)
{
    uint8_t public_key_encoded[133];  /* Max: 1 + 2*66 for P-521 */
    uint32_t public_key_len = (uint32_t)sizeof(public_key_encoded);
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t offset = 0U;
    uint32_t required_len = 0U;
    
    if ((ecdhe_ctx == NULL) || (output == NULL) || (output_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Get encoded public key */
    rc = noxtls_tls_ecdhe_get_public_key_encoded(ecdhe_ctx, public_key_encoded, &public_key_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    required_len = 2U + 2U + public_key_len;  /* Group + length + key exchange */
    
    if (*output_len < required_len) {
        *output_len = required_len;
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Group (2 bytes) */
    output[offset] = (uint8_t)(((uint32_t)ecdhe_ctx->named_group >> 8U) & 0xFFU);
    offset += 1U;
    output[offset] = (uint8_t)(ecdhe_ctx->named_group & 0xFFU);
    offset += 1U;
    
    /* Key exchange length (2 bytes) */
    output[offset] = (uint8_t)((public_key_len >>8U) & 0xFFU);
    offset += 1U;
    output[offset] = (uint8_t)(public_key_len & 0xFFU);
    offset += 1U;
    
    /* Key exchange */
    noxtls_copy_u8(&output[offset], (size_t)(*output_len), public_key_encoded, (size_t)(public_key_len));
    offset += public_key_len;
    
    *output_len = offset;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3: decode KeyShareEntry for NIST curves into an uncompressed ECC point.
 * @param[in] encoded KeyShareEntry bytes.
 * @param[in] encoded_len Length of @p encoded.
 * @param[in] named_group Expected named group (must match wire group field).
 * @param[out] public_key Decoded peer public point (not used for X25519/X448; those return failure here).
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on mismatch, short input, Montgomery groups, or decode errors.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_tls13_key_share_decode(const uint8_t *encoded, uint32_t encoded_len, uint16_t named_group, ecc_point_t *public_key)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint16_t group = 0U;
    uint16_t key_exchange_len = 0U;
    ecc_curve_t curve_type = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    if ((encoded == NULL) || (public_key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    if (encoded_len < 4U) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Group (2 bytes) */
    group = ((uint16_t)encoded[0] << 8U) | (uint16_t)encoded[1];
    
    /* Verify group matches */
    if (group != named_group) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Key exchange length (2 bytes) */
    key_exchange_len = ((uint16_t)encoded[2] << 8U) | (uint16_t)encoded[3];
    
    {
        uint32_t required_len = (uint32_t)key_exchange_len + 4U;
        if (encoded_len < required_len) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    
    /* X25519 key share is 32 raw bytes; decode API returns ECC point, so not applicable */
    if ((named_group == TLS_NAMED_GROUP_X25519) || (named_group == TLS_NAMED_GROUP_X448)) {
        uint16_t expected = (uint16_t)((named_group == TLS_NAMED_GROUP_X25519) ? NOXTLS_X25519_KEY_SIZE : NOXTLS_X448_KEY_SIZE);
        if (key_exchange_len != expected) {
            return NOXTLS_RETURN_FAILED;
        }
        /* Caller should use key_exchange bytes directly with RFC 7748 shared-secret APIs. */
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Map named group to curve type */
    rc = noxtls_tls_named_group_to_ecc_curve(named_group, &curve_type);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    /* Decode public key */
    return noxtls_tls_decode_ecc_point_uncompressed(&encoded[4], key_exchange_len, public_key, curve_type);
}

/**
 * @brief TLS 1.3 server: find matching client KeyShare and compute shared secret.
 * @param[in,out] ctx TLS 1.3 server context with parsed client key shares.
 * @param[in,out] ecdhe_ctx Local ECDHE context for the negotiated group.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on role mismatch, missing share, or ECDH failure.
 */
noxtls_return_t noxtls_tls13_process_client_key_share(tls13_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx)
{
    ecc_point_t peer_public_key;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    if ((ctx == NULL) || (ecdhe_ctx == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    if (ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if ((ctx->client_key_shares == NULL) || (ctx->client_key_shares_count == 0U)) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Find matching key share */
    uint32_t i = 0U;
    const tls13_key_share_entry_t *client_key_share = NULL;
    for (i = 0U; i < ctx->client_key_shares_count; i += 1U) {
        if (ctx->client_key_shares[i].group == ecdhe_ctx->named_group) {
            client_key_share = &ctx->client_key_shares[i];
            break;
        }
    }
    
    if (client_key_share == NULL) {
        return NOXTLS_RETURN_FAILED;  /* No matching key share found */
    }
    
    if (ecdhe_ctx->named_group == TLS_NAMED_GROUP_X25519) {
        if (client_key_share->key_exchange_len != NOXTLS_X25519_KEY_SIZE) {
            return NOXTLS_RETURN_FAILED;
        }
        return noxtls_tls_ecdhe_compute_shared_secret_x25519(ecdhe_ctx, client_key_share->key_exchange);
    }
    if (ecdhe_ctx->named_group == TLS_NAMED_GROUP_X448) {
        if (client_key_share->key_exchange_len != NOXTLS_X448_KEY_SIZE) {
            return NOXTLS_RETURN_FAILED;
        }
        return noxtls_tls_ecdhe_compute_shared_secret_x448(ecdhe_ctx, client_key_share->key_exchange);
    }
    
    /* Decode client's public key (raw key_exchange bytes) */
    ecc_curve_t curve_type = 0U;
    rc = noxtls_tls_named_group_to_ecc_curve(ecdhe_ctx->named_group, &curve_type);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_tls_decode_ecc_point_uncompressed(client_key_share->key_exchange,
                                           client_key_share->key_exchange_len,
                                           &peer_public_key,
                                           curve_type);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    /* Compute shared secret */
    return noxtls_tls_ecdhe_compute_shared_secret(ecdhe_ctx, &peer_public_key);
}

/**
 * @brief TLS 1.3 client: consume server KeyShare and compute shared secret.
 * @param[in] ctx TLS 1.3 client context with parsed server share.
 * @param[in,out] ecdhe_ctx Local ECDHE context for the negotiated group.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on role mismatch, missing share, or ECDH failure.
 */
noxtls_return_t noxtls_tls13_process_server_key_share(const tls13_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx)
{
    ecc_point_t peer_public_key;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    if ((ctx == NULL) || (ecdhe_ctx == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    if (ctx->base.base.role != TLS_ROLE_CLIENT) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if (ctx->server_key_share == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Verify group matches */
    if (ctx->server_key_share->group != ecdhe_ctx->named_group) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if (ecdhe_ctx->named_group == TLS_NAMED_GROUP_X25519) {
        if (ctx->server_key_share->key_exchange_len != NOXTLS_X25519_KEY_SIZE) {
            return NOXTLS_RETURN_FAILED;
        }
        return noxtls_tls_ecdhe_compute_shared_secret_x25519(ecdhe_ctx, ctx->server_key_share->key_exchange);
    }
    if (ecdhe_ctx->named_group == TLS_NAMED_GROUP_X448) {
        if (ctx->server_key_share->key_exchange_len != NOXTLS_X448_KEY_SIZE) {
            return NOXTLS_RETURN_FAILED;
        }
        return noxtls_tls_ecdhe_compute_shared_secret_x448(ecdhe_ctx, ctx->server_key_share->key_exchange);
    }
    
    /* Decode server's public key (raw key_exchange bytes) */
    ecc_curve_t curve_type = 0U;
    rc = noxtls_tls_named_group_to_ecc_curve(ecdhe_ctx->named_group, &curve_type);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_tls_decode_ecc_point_uncompressed(ctx->server_key_share->key_exchange,
                                           ctx->server_key_share->key_exchange_len,
                                           &peer_public_key,
                                           curve_type);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if ((ecdhe_ctx->ephemeral_key.d != NULL) && (ecdhe_ctx->ephemeral_key.curve != NULL)) {
        uint32_t size = (uint32_t)(ecdhe_ctx->ephemeral_key.curve->size);
        (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] ecdhe d=");
        for (uint32_t i = 0U; i < size; i += 1U) {
            (void)noxtls_debug_printf((const uint8_t *)"%02X", ecdhe_ctx->ephemeral_key.d[i]);
        }
        (void)noxtls_debug_printf((const uint8_t *)"\n");
        (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] ecdhe peer_x=");
        for (uint32_t i = 0U; i < size; i += 1U) {
            (void)noxtls_debug_printf((const uint8_t *)"%02X", peer_public_key.x[i]);
        }
        (void)noxtls_debug_printf((const uint8_t *)"\n");
        (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] ecdhe peer_y=");
        for (uint32_t i = 0U; i < size; i += 1U) {
            (void)noxtls_debug_printf((const uint8_t *)"%02X", peer_public_key.y[i]);
        }
        (void)noxtls_debug_printf((const uint8_t *)"\n");
    }
    
    /* Compute shared secret */
    return noxtls_tls_ecdhe_compute_shared_secret(ecdhe_ctx, &peer_public_key);
}
