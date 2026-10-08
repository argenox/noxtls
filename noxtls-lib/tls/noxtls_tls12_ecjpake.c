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
* File:    noxtls_tls12_ecjpake.c
* Summary: TLS_ECJPAKE_WITH_AES_128_CCM_8 handshake content for TLS 1.2 / DTLS 1.2
*
*
*****************************************************************************/

/**
 * @file noxtls_tls12_ecjpake.c
 * @brief EC-JPAKE ClientHello / ServerHello extensions, key exchange bodies and key export.
 * @ingroup noxtls_tls12_ecjpake
 *
 * draft-cragie-tls-ecjpake-01 (June 2016):
 * - section 7.2.1: ClientHello carries supported_groups (one entry) and
 *   ec_point_formats (RFC 4492 section 4 / RFC 8422 section 5.1);
 * - section 7.2.2: ecjpake_key_kp_pair in ClientHello and ServerHello;
 * - section 7.3: ServerKeyExchange = ServerECJPAKEParams;
 * - section 7.4: ClientKeyExchange = ClientECJPAKEParams;
 * - section 8.7: premaster secret;
 * - section 6: any failure aborts the handshake with a fatal alert.
 * Key block layout: RFC 5246 section 6.3; AES-128-CCM-8 sizes: RFC 6655
 * section 3.
 */

#include <stdint.h>

#include "noxtls_tls12_ecjpake_internal.h"
#include "noxtls_tls_common.h"
#include "common/noxtls_ct.h"
#include "common/noxtls_memory.h"

/** @brief Bits in one byte shift, for big-endian 16-bit fields. */
#define NOXTLS_TLS12_ECJPAKE_BYTE_SHIFT (8U)
/** @brief Mask selecting one byte. */
#define NOXTLS_TLS12_ECJPAKE_BYTE_MASK (0xFFU)
/** @brief Size of a NamedGroup / ExtensionType value. */
#define NOXTLS_TLS12_ECJPAKE_U16_SIZE (2U)
/** @brief ECPointFormat uncompressed (RFC 8422 section 5.1.2). */
#define NOXTLS_TLS12_ECJPAKE_POINT_FORMAT_UNCOMPRESSED (0U)
/** @brief AES-128-CCM-8 key length (RFC 6655 section 3). */
#define NOXTLS_TLS12_ECJPAKE_KEY_LEN (16U)
/** @brief AES-128-CCM-8 implicit (fixed) IV length (RFC 6655 section 3). */
#define NOXTLS_TLS12_ECJPAKE_IV_LEN (4U)

/**
 * @brief Write a big-endian 16-bit value.
 * @internal
 *
 * @param[out] out Destination (2 octets).
 * @param[in] value Value.
 */
static void tls12_ecjpake_put_u16(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)((value >> NOXTLS_TLS12_ECJPAKE_BYTE_SHIFT) & NOXTLS_TLS12_ECJPAKE_BYTE_MASK);
    out[1] = (uint8_t)(value & NOXTLS_TLS12_ECJPAKE_BYTE_MASK);
}

/**
 * @brief Write an extension header (type, length).
 * @internal
 *
 * @param[out] out Destination (4 octets).
 * @param[in] type Extension type.
 * @param[in] body_len Extension body length.
 */
static void tls12_ecjpake_put_ext_header(uint8_t *out, uint32_t type, uint32_t body_len)
{
    tls12_ecjpake_put_u16(out, type);
    tls12_ecjpake_put_u16(&out[NOXTLS_TLS12_ECJPAKE_U16_SIZE], body_len);
}

int tls12_ecjpake_active(const tls12_context_t *ctx)
{
    return ((ctx != NULL) && (ctx->ecjpake != NULL)) ? 1 : 0;
}

int noxtls_tls12_ecjpake_negotiated(const tls12_context_t *ctx)
{
    return ((tls12_ecjpake_active(ctx) != 0) &&
            (ctx->cipher_suite == TLS_CIPHER_SUITE_ECJPAKE_WITH_AES_128_CCM_8)) ? 1 : 0;
}

noxtls_return_t noxtls_tls12_set_ecjpake_password(tls12_context_t *ctx,
                                                  const uint8_t *password,
                                                  uint32_t password_len)
{
    noxtls_ecjpake_role_t role;
    noxtls_return_t rc;

    if ((ctx == NULL) || (password == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (ctx->base.base.state != TLS_STATE_INIT) {
        return NOXTLS_RETURN_FAILED;
    }

    if (ctx->ecjpake == NULL) {
        ctx->ecjpake = (noxtls_ecjpake_ctx_t *)NOXTLS_MALLOC(sizeof(noxtls_ecjpake_ctx_t));
        if (ctx->ecjpake == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }

    role = (ctx->base.base.role == TLS_ROLE_SERVER) ? NOXTLS_ECJPAKE_ROLE_SERVER : NOXTLS_ECJPAKE_ROLE_CLIENT;
    rc = noxtls_ecjpake_init(ctx->ecjpake, role, password, password_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        tls12_ecjpake_release(ctx);
    }

    return rc;
}

void tls12_ecjpake_release(tls12_context_t *ctx)
{
    if ((ctx != NULL) && (ctx->ecjpake != NULL)) {
        noxtls_ecjpake_free(ctx->ecjpake);
        noxtls_free(ctx->ecjpake);
        ctx->ecjpake = NULL;
    }
}

uint8_t tls12_ecjpake_alert_for(noxtls_return_t rc)
{
    uint8_t alert = (uint8_t)TLS_ALERT_INTERNAL_ERROR;

    if (rc == NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR) {
        alert = (uint8_t)TLS_ALERT_DECODE_ERROR;
    } else if (rc == NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER) {
        alert = (uint8_t)TLS_ALERT_ILLEGAL_PARAMETER;
    } else if (rc == NOXTLS_RETURN_NOT_SUPPORTED) {
        alert = (uint8_t)TLS_ALERT_HANDSHAKE_FAILURE;
    } else {
        /* MISRA C:2025 Rule 15.7: remaining codes are local failures. */
    }

    return alert;
}

noxtls_return_t tls12_ecjpake_write_client_hello_extensions(tls12_context_t *ctx, uint8_t *out,
                                                            uint32_t out_size, uint32_t *out_len)
{
    uint32_t offset = 0U;
    uint32_t r1_len = 0U;
    uint32_t fixed = (2U * NOXTLS_TLS12_ECJPAKE_EXT_HEADER_SIZE) + NOXTLS_TLS12_ECJPAKE_GROUPS_BODY_SIZE +
                     NOXTLS_TLS12_ECJPAKE_POINT_FORMATS_BODY_SIZE + NOXTLS_TLS12_ECJPAKE_EXT_HEADER_SIZE;
    noxtls_return_t rc;

    if ((tls12_ecjpake_active(ctx) == 0) || (out == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (out_size < NOXTLS_TLS12_ECJPAKE_CLIENT_HELLO_EXT_MAX_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    /* draft section 7.2.1: EllipticCurveList with exactly the one fixed curve (RFC 8422 section 5.1.1). */
    tls12_ecjpake_put_ext_header(&out[offset], TLS_EXTENSION_SUPPORTED_GROUPS, NOXTLS_TLS12_ECJPAKE_GROUPS_BODY_SIZE);
    offset += NOXTLS_TLS12_ECJPAKE_EXT_HEADER_SIZE;
    tls12_ecjpake_put_u16(&out[offset], NOXTLS_TLS12_ECJPAKE_U16_SIZE);
    tls12_ecjpake_put_u16(&out[offset + NOXTLS_TLS12_ECJPAKE_U16_SIZE], TLS_NAMED_GROUP_SECP256R1);
    offset += NOXTLS_TLS12_ECJPAKE_GROUPS_BODY_SIZE;

    /* draft section 7.2.1: ECPointFormatList { uncompressed } (RFC 8422 section 5.1.2). */
    tls12_ecjpake_put_ext_header(&out[offset], TLS_EXTENSION_EC_POINT_FORMATS,
                                 NOXTLS_TLS12_ECJPAKE_POINT_FORMATS_BODY_SIZE);
    offset += NOXTLS_TLS12_ECJPAKE_EXT_HEADER_SIZE;
    out[offset] = 1U;
    out[offset + 1U] = (uint8_t)NOXTLS_TLS12_ECJPAKE_POINT_FORMAT_UNCOMPRESSED;
    offset += NOXTLS_TLS12_ECJPAKE_POINT_FORMATS_BODY_SIZE;

    /* draft section 7.2.2: ecjpake_key_kp_pair = round one (identity elided). The
     * same octets are returned after a HelloVerifyRequest. */
    rc = noxtls_ecjpake_write_round_one(ctx->ecjpake, &out[fixed], out_size - fixed, &r1_len);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        tls12_ecjpake_put_ext_header(&out[offset], TLS_EXTENSION_ECJPAKE_KEY_KP_PAIR, r1_len);
        *out_len = fixed + r1_len;
    }

    return rc;
}

noxtls_return_t tls12_ecjpake_client_read_server_hello_extension(tls12_context_t *ctx, const uint8_t *data,
                                                                 uint32_t len)
{
    if ((tls12_ecjpake_active(ctx) == 0) || (data == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    /* draft section 8.4.3: verify both server ZKPs ("server" identity). */
    return noxtls_ecjpake_read_round_one(ctx->ecjpake, data, len);
}

noxtls_return_t tls12_ecjpake_client_read_server_key_exchange(tls12_context_t *ctx, const uint8_t *body,
                                                              uint32_t len)
{
    if ((tls12_ecjpake_active(ctx) == 0) || (body == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    /* draft section 7.3 / 8.5.3: ServerECJPAKEParams, ZKP over GB = X1 + X2 + X3. */
    return noxtls_ecjpake_read_round_two(ctx->ecjpake, body, len);
}

/**
 * @brief Derive the premaster secret into the TLS context (draft section 8.7).
 * @internal
 *
 * @param[in,out] ctx TLS 1.2 context with both EC-JPAKE rounds complete.
 *
 * @return NOXTLS_RETURN_SUCCESS or an error code.
 */
static noxtls_return_t tls12_ecjpake_store_premaster(tls12_context_t *ctx)
{
    uint32_t pms_len = 0U;
    noxtls_return_t rc;

    rc = noxtls_ecjpake_derive_premaster(ctx->ecjpake, ctx->premaster_secret,
                                         (uint32_t)sizeof(ctx->premaster_secret), &pms_len);
    ctx->premaster_secret_len = (rc == NOXTLS_RETURN_SUCCESS) ? pms_len : 0U;
    return rc;
}

noxtls_return_t tls12_ecjpake_client_write_key_exchange(tls12_context_t *ctx, uint8_t *out,
                                                        uint32_t out_size, uint32_t *out_len)
{
    noxtls_return_t rc;

    if ((tls12_ecjpake_active(ctx) == 0) || (out == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    /* draft section 7.4 / 8.6: ClientECJPAKEParams, then PMS (section 8.7.2). */
    rc = noxtls_ecjpake_write_round_two(ctx->ecjpake, out, out_size, out_len);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = tls12_ecjpake_store_premaster(ctx);
    }

    return rc;
}

/**
 * @brief Return 1 when a parsed supported_groups extension lists secp256r1.
 * @internal
 *
 * @param[in] groups Parsed extension.
 *
 * @return 1 when secp256r1 is offered, 0 otherwise.
 */
static int tls12_ecjpake_groups_offer_p256(const tls_supported_groups_extension_t *groups)
{
    uint32_t index;
    int found = 0;

    for (index = 0U; (index < groups->count) && (found == 0); ++index) {
        if (groups->groups[index] == TLS_NAMED_GROUP_SECP256R1) {
            found = 1;
        }
    }

    return found;
}

noxtls_return_t tls12_ecjpake_server_process_client_hello(tls12_context_t *ctx)
{
    tls_extension_t *kkpp = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint8_t alert = (uint8_t)TLS_ALERT_HANDSHAKE_FAILURE;

    if (tls12_ecjpake_active(ctx) == 0) {
        return NOXTLS_RETURN_NULL;
    }

    /* EC-JPAKE authenticates with the password only (draft section 5: no
     * Certificate or CertificateRequest), so client authentication settings conflict. */
    if ((ctx->request_client_auth != 0U) || (ctx->require_client_auth != 0U)) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    } else if ((ctx->client_extensions.supported_groups != NULL) &&
               (tls12_ecjpake_groups_offer_p256(ctx->client_extensions.supported_groups) == 0)) {
        /* draft section 7.2.1 / RFC 8422 section 5.1.1: the fixed curve must be offered. */
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    } else if ((noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_ECJPAKE_KEY_KP_PAIR, &kkpp) !=
                NOXTLS_RETURN_SUCCESS) || (kkpp == NULL) || (kkpp->data == NULL)) {
        /* draft section 7.2.2 / section 6: the extension SHALL be present. */
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
        alert = (uint8_t)TLS_ALERT_MISSING_EXTENSION;
    } else {
        /* draft section 8.4.3: verify both client ZKPs ("client" identity). */
        rc = noxtls_ecjpake_read_round_one(ctx->ecjpake, kkpp->data, kkpp->length);
        alert = tls12_ecjpake_alert_for(rc);
    }

    if ((rc != NOXTLS_RETURN_SUCCESS) && (ctx->base.base.send_callback != NULL)) {
        (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, alert);
    }

    return rc;
}

noxtls_return_t tls12_ecjpake_write_server_hello_extension(tls12_context_t *ctx, uint8_t *out,
                                                           uint32_t out_size, uint32_t *out_len)
{
    uint32_t r1_len = 0U;
    noxtls_return_t rc;

    if ((tls12_ecjpake_active(ctx) == 0) || (out == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (out_size < NOXTLS_TLS12_ECJPAKE_EXT_HEADER_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    /* draft section 7.2.2: the server round one (X3, X4 with ZKPs) in ServerHello. */
    rc = noxtls_ecjpake_write_round_one(ctx->ecjpake, &out[NOXTLS_TLS12_ECJPAKE_EXT_HEADER_SIZE],
                                        out_size - NOXTLS_TLS12_ECJPAKE_EXT_HEADER_SIZE, &r1_len);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        tls12_ecjpake_put_ext_header(out, TLS_EXTENSION_ECJPAKE_KEY_KP_PAIR, r1_len);
        *out_len = NOXTLS_TLS12_ECJPAKE_EXT_HEADER_SIZE + r1_len;
    }

    return rc;
}

noxtls_return_t tls12_ecjpake_server_write_key_exchange(tls12_context_t *ctx, uint8_t *out,
                                                        uint32_t out_size, uint32_t *out_len)
{
    if ((tls12_ecjpake_active(ctx) == 0) || (out == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    /* draft section 7.3 / 8.5: ServerECJPAKEParams, no signature. */
    return noxtls_ecjpake_write_round_two(ctx->ecjpake, out, out_size, out_len);
}

noxtls_return_t tls12_ecjpake_server_read_client_key_exchange(tls12_context_t *ctx, const uint8_t *body,
                                                              uint32_t len)
{
    noxtls_return_t rc;

    if ((tls12_ecjpake_active(ctx) == 0) || (body == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    /* draft section 7.4 / 8.6.3: ClientECJPAKEParams, then PMS (section 8.7.1). */
    rc = noxtls_ecjpake_read_round_two(ctx->ecjpake, body, len);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = tls12_ecjpake_store_premaster(ctx);
    }

    return rc;
}

noxtls_return_t noxtls_tls12_ecjpake_export_key_block(const tls12_context_t *ctx,
                                                      uint8_t *out,
                                                      uint32_t out_size,
                                                      uint32_t *out_len)
{
    uint32_t offset = 0U;

    if ((ctx == NULL) || (out == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if ((ctx->base.base.state != TLS_STATE_CONNECTED) || (noxtls_tls12_ecjpake_negotiated(ctx) == 0)) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    if (out_size < NOXTLS_TLS12_ECJPAKE_KEY_BLOCK_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    /* RFC 5246 section 6.3 key_block order; MAC keys are empty for AEAD (RFC 6655 section 3). */
    noxtls_copy_u8(&out[offset], NOXTLS_TLS12_ECJPAKE_KEY_LEN, ctx->client_write_key, NOXTLS_TLS12_ECJPAKE_KEY_LEN);
    offset += NOXTLS_TLS12_ECJPAKE_KEY_LEN;
    noxtls_copy_u8(&out[offset], NOXTLS_TLS12_ECJPAKE_KEY_LEN, ctx->server_write_key, NOXTLS_TLS12_ECJPAKE_KEY_LEN);
    offset += NOXTLS_TLS12_ECJPAKE_KEY_LEN;
    noxtls_copy_u8(&out[offset], NOXTLS_TLS12_ECJPAKE_IV_LEN, ctx->client_write_iv, NOXTLS_TLS12_ECJPAKE_IV_LEN);
    offset += NOXTLS_TLS12_ECJPAKE_IV_LEN;
    noxtls_copy_u8(&out[offset], NOXTLS_TLS12_ECJPAKE_IV_LEN, ctx->server_write_iv, NOXTLS_TLS12_ECJPAKE_IV_LEN);
    offset += NOXTLS_TLS12_ECJPAKE_IV_LEN;
    *out_len = offset;
    return NOXTLS_RETURN_SUCCESS;
}
