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
* File:    noxtls_efr32_port_ecc.c
* Summary: NoxTLS ECC accelerator ports on the EFR32xG2x Secure Engine
*
*****************************************************************************/

/**
 * @file noxtls_efr32_port_ecc.c
 * @brief ECC point multiplication, ECDSA sign / verify and ECDH ports served by the
 *        Secure Engine on NIST P-256 and P-384.
 * @ingroup noxtls_efr32
 *
 * Point multiplication (key generation, ECDH inside NoxTLS) uses SE_COMMAND_DH,
 * which returns the complete shared point. With NOXTLS_EFR32_CONFIG_PTMUL_DOUBLE_CHECK
 * the multiplication is repeated and accepted only when both results agree
 * (a successful response does not authenticate the arithmetic; a transient fault
 * could otherwise publish a valid-looking wrong point). Any failure returns
 * NOT_SUPPORTED and the portable NoxTLS path recomputes.
 *
 * ECDSA verification: an SE "invalid signature" response is final (FAILED); any
 * other error falls back to software. ECDSA signing uses the SE with a nonce
 * the SE draws from its TRNG (NOXTLS_EFR32_CONFIG_SE_ECDSA_SIGN); the digest
 * passed by NoxTLS is already reduced to the order length. Ed25519 and X25519
 * have no hook that matches the SE commands (the Ed25519 hook receives
 * SHA-512(R || A || M), the SE hashes the message itself) and stay in software.
 */

#include <stddef.h>
#include <string.h>

#include "noxtls_ecc.h"
#include "noxtls_ecdh.h"
#include "noxtls_ecdsa_accel_port.h"
#include "noxtls_efr32_se_ops.h"

/** NIST P-256 prime p (SP 800-186 §3.2.1.3), big-endian. */
static const uint8_t s_noxtls_efr32_p256_p[NOXTLS_EFR32_SE_P256_BYTES] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};

/** NIST P-384 prime p = 2^384 - 2^128 - 2^96 + 2^32 - 1 (SP 800-186 §3.2.1.4), big-endian. */
static const uint8_t s_noxtls_efr32_p384_p[NOXTLS_EFR32_SE_P384_BYTES] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};

/** Point-multiply port telemetry (NoxTLS noxtls_ecc_accel_* interface). */
typedef struct {
    uint32_t operations;   /**< Accelerated multiplications. */
    uint32_t fallbacks;    /**< Requests continued in software. */
    int32_t last_rc;       /**< Result of the last attempt. */
    uint32_t last_stage;   /**< Last stage reached (2 first run, 3 second run, 4 done). */
    uint8_t ready;         /**< Non-zero after a successful multiplication. */
} noxtls_efr32_port_ecc_t;

/** Telemetry. */
static noxtls_efr32_port_ecc_t s_noxtls_efr32_port_ecc = { 0U, 0U, (int32_t)NOXTLS_RETURN_NOT_SUPPORTED, 0U, 0U };

/** @brief Stage: first multiplication. */
#define NOXTLS_EFR32_PORT_STAGE_FIRST   2U
/** @brief Stage: check multiplication. */
#define NOXTLS_EFR32_PORT_STAGE_CHECK   3U
/** @brief Stage: accepted. */
#define NOXTLS_EFR32_PORT_STAGE_DONE    4U

/**
 * @brief Whether curve parameters are NIST P-256 or P-384.
 * @internal
 *
 * @param[in] curve Curve.
 *
 * @return Coordinate bytes (32 or 48), 0 for another curve.
 */
static uint32_t noxtls_efr32_port_curve_size(const ecc_curve_params_t *curve)
{
    uint32_t size = 0U;

    if ((curve != NULL) && (curve->p != NULL) && (curve->size <= (uint32_t)ECC_MAX_KEY_SIZE)) {
        if ((curve->size == NOXTLS_EFR32_SE_P256_BYTES) &&
            (memcmp(curve->p, s_noxtls_efr32_p256_p, sizeof(s_noxtls_efr32_p256_p)) == 0)) {
            size = NOXTLS_EFR32_SE_P256_BYTES;
        } else if ((curve->size == NOXTLS_EFR32_SE_P384_BYTES) &&
                   (memcmp(curve->p, s_noxtls_efr32_p384_p, sizeof(s_noxtls_efr32_p384_p)) == 0)) {
            size = NOXTLS_EFR32_SE_P384_BYTES;
        } else {
            /* Not a curve of the SE. */
        }
    }
    return size;
}

int noxtls_ecc_accel_is_ready(void)
{
    return (s_noxtls_efr32_port_ecc.ready != 0U) ? 1 : 0;
}

uint32_t noxtls_ecc_accel_operation_count(void)
{
    return s_noxtls_efr32_port_ecc.operations;
}

uint32_t noxtls_ecc_accel_fallback_count(void)
{
    return s_noxtls_efr32_port_ecc.fallbacks;
}

void noxtls_ecc_accel_note_fallback(void)
{
    s_noxtls_efr32_port_ecc.fallbacks++;
}

int32_t noxtls_ecc_accel_last_rc(void)
{
    return s_noxtls_efr32_port_ecc.last_rc;
}

uint32_t noxtls_ecc_accel_last_status(void)
{
    return (uint32_t)noxtls_efr32_stats()->se_errors;
}

uint32_t noxtls_ecc_accel_last_stage(void)
{
    return s_noxtls_efr32_port_ecc.last_stage;
}

int noxtls_ecc_accel_input_echo_ok(void)
{
    /* Operands are staged in module buffers; no echo check is needed. */
    return 1;
}

noxtls_return_t noxtls_ecc_point_multiply_accel_port(ecc_point_t *result,
                                                      const uint8_t *scalar,
                                                      const ecc_point_t *point,
                                                      const ecc_curve_params_t *curve)
{
    noxtls_efr32_port_ecc_t *st = &s_noxtls_efr32_port_ecc;
    uint32_t size = noxtls_efr32_port_curve_size(curve);
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if ((result != NULL) && (scalar != NULL) && (point != NULL) && (size != 0U) && (point->size == size)) {
        st->last_stage = NOXTLS_EFR32_PORT_STAGE_FIRST;
        rc = noxtls_efr32_se_ecc_mul(size, scalar, point->x, point->y, result->x, result->y);
#if (NOXTLS_EFR32_CONFIG_PTMUL_DOUBLE_CHECK != 0)
        if (rc == NOXTLS_RETURN_SUCCESS) {
            uint8_t check_x[NOXTLS_EFR32_SE_COORD_MAX];
            uint8_t check_y[NOXTLS_EFR32_SE_COORD_MAX];

            st->last_stage = NOXTLS_EFR32_PORT_STAGE_CHECK;
            rc = noxtls_efr32_se_ecc_mul(size, scalar, point->x, point->y, check_x, check_y);
            if ((rc == NOXTLS_RETURN_SUCCESS) &&
                ((memcmp(check_x, result->x, size) != 0) || (memcmp(check_y, result->y, size) != 0))) {
                rc = NOXTLS_RETURN_FAILED;
            }
            noxtls_efr32_wipe(check_x, (uint32_t)sizeof(check_x));
            noxtls_efr32_wipe(check_y, (uint32_t)sizeof(check_y));
        }
#endif
        if ((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_efr32_is_zero(result->x, size) != 0U) &&
            (noxtls_efr32_is_zero(result->y, size) != 0U)) {
            /* The point at infinity is never published from the SE: the portable path decides. */
            rc = NOXTLS_RETURN_FAILED;
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            result->size = size;
            st->operations++;
            st->ready = 1U;
            st->last_stage = NOXTLS_EFR32_PORT_STAGE_DONE;
        } else {
            noxtls_efr32_wipe(result->x, size);
            noxtls_efr32_wipe(result->y, size);
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        }
        st->last_rc = (int32_t)rc;
    }
    return rc;
}

noxtls_return_t noxtls_ecdsa_sign_accel_port(const ecc_key_t *key,
                                             const uint8_t *hash,
                                             uint32_t hash_len,
                                             ecdsa_signature_t *signature)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint32_t size = (key != NULL) ? noxtls_efr32_port_curve_size(key->curve) : 0U;

    if ((NOXTLS_EFR32_CONFIG_SE_ECDSA_SIGN != 0) && (key != NULL) && (key->d != NULL) && (hash != NULL) &&
        (signature != NULL) && (size != 0U) && (hash_len == size)) {
        rc = noxtls_efr32_se_ecdsa_sign(size, key->d, hash, signature->r, signature->s);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            signature->size = size;
        } else {
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        }
    }
    return rc;
}

noxtls_return_t noxtls_ecdsa_verify_accel_port(const ecc_key_t *key,
                                               const uint8_t *hash,
                                               uint32_t hash_len,
                                               const ecdsa_signature_t *signature)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint32_t size = (key != NULL) ? noxtls_efr32_port_curve_size(key->curve) : 0U;

    if ((key != NULL) && (hash != NULL) && (signature != NULL) && (size != 0U) && (hash_len == size)) {
        rc = noxtls_efr32_se_ecdsa_verify(size, key->Q.x, key->Q.y, hash, signature->r, signature->s);
        if (rc == NOXTLS_RETURN_BAD_DATA) {
            rc = NOXTLS_RETURN_FAILED;
        } else if (rc != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        } else {
            /* Valid signature. */
        }
    }
    return rc;
}

noxtls_return_t noxtls_ecdh_compute_shared_secret_accel_port(const ecc_key_t *private_key,
                                                             const ecc_point_t *peer_public_key,
                                                             uint8_t *shared_secret,
                                                             uint32_t *shared_secret_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint32_t size = (private_key != NULL) ? noxtls_efr32_port_curve_size(private_key->curve) : 0U;

    if ((private_key != NULL) && (private_key->d != NULL) && (peer_public_key != NULL) && (shared_secret != NULL) &&
        (shared_secret_len != NULL) && (size != 0U) && (peer_public_key->size == size) && (*shared_secret_len >= size)) {
        uint8_t y[NOXTLS_EFR32_SE_COORD_MAX];

        rc = noxtls_efr32_se_ecc_mul(size, private_key->d, peer_public_key->x, peer_public_key->y, shared_secret, y);
        noxtls_efr32_wipe(y, (uint32_t)sizeof(y));
        if ((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_efr32_is_zero(shared_secret, size) == 0U)) {
            *shared_secret_len = size;
            rc = NOXTLS_RETURN_SUCCESS;
        } else {
            /* A failure, or the point at infinity (all-zero x): the portable path decides. */
            noxtls_efr32_wipe(shared_secret, size);
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        }
    }
    return rc;
}
