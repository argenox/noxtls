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
* File:    noxtls_efr32_se_ecc.c
* Summary: EFR32xG2x Secure Engine ECDH point multiplication and ECDSA on P-256 / P-384
*
*****************************************************************************/

/**
 * @file noxtls_efr32_se_ecc.c
 * @brief SE_COMMAND_DH (full point k * P), SE_COMMAND_SIGN and SE_COMMAND_VERIFY with
 *        plaintext keys on NIST P-256 and P-384.
 * @ingroup noxtls_efr32
 *
 * Encodings (Simplicity SDK v2025.6.3 sl_se_manager_key_handling.c,
 * sl_se_manager_signature.c, sl_se_manager_key_derivation.c and
 * sl_psa_driver/sli_se_driver_key_derivation.c, Zlib, re-expressed):
 *  - keyspec = Weierstrass type | private / public flag | (coordinate bytes - 1);
 *    a raw output key uses its byte count as keyspec.
 *  - Every key command carries an empty "authorization" input transfer first
 *    (plaintext keys need no password), then the key, then the data.
 *  - DH: parameters [private keyspec without the reserved bits, output raw
 *    keyspec]; inputs [auth, private key, peer public key X || Y]; output the
 *    shared point X || Y (2 coordinates), so one command is a complete point
 *    multiplication.
 *  - SIGN: parameters [private keyspec, message length]; inputs [auth, private key,
 *    digest]; output r || s. The digest is passed without a hash option (the
 *    message is already a digest).
 *  - VERIFY: parameters [public keyspec, message length]; inputs [auth, public key
 *    X || Y, digest, signature r || s].
 * The SE reports random point-multiplication failures for extreme scalars; the
 * multiplication is retried (NOXTLS_EFR32_CONFIG_SE_PTMUL_RETRIES).
 */

#include <stddef.h>
#include <string.h>

#include "noxtls_efr32_se_ops.h"

/** @brief Coordinates per point. */
#define NOXTLS_EFR32_ECC_POINT_COORDS   2U

/** Staging buffers of the ECC commands (owned while the mailbox is held). */
static struct {
    noxtls_efr32_se_xfer_t auth;                                        /**< Empty authorization transfer. */
    noxtls_efr32_se_xfer_t key;                                         /**< Key transfer. */
    noxtls_efr32_se_xfer_t pub;                                         /**< Peer public key transfer. */
    noxtls_efr32_se_xfer_t msg;                                         /**< Digest transfer. */
    noxtls_efr32_se_xfer_t sig;                                         /**< Signature transfer. */
    noxtls_efr32_se_xfer_t out;                                         /**< Output transfer. */
    uint8_t key_buf[NOXTLS_EFR32_ECC_POINT_COORDS * NOXTLS_EFR32_SE_COORD_MAX]; /**< Private or public key. */
    uint8_t pub_buf[NOXTLS_EFR32_ECC_POINT_COORDS * NOXTLS_EFR32_SE_COORD_MAX]; /**< Peer public key. */
    uint8_t msg_buf[NOXTLS_EFR32_SE_COORD_MAX];                         /**< Digest. */
    uint8_t sig_buf[NOXTLS_EFR32_ECC_POINT_COORDS * NOXTLS_EFR32_SE_COORD_MAX]; /**< Signature. */
    uint8_t out_buf[NOXTLS_EFR32_ECC_POINT_COORDS * NOXTLS_EFR32_SE_COORD_MAX]; /**< Command output. */
} s_noxtls_efr32_ecc;

/**
 * @brief Whether a coordinate size is supported.
 * @internal
 *
 * @param[in] size Bytes.
 *
 * @return 1 for 32 or 48.
 */
static uint8_t noxtls_efr32_ecc_size_ok(uint32_t size)
{
    return ((size == NOXTLS_EFR32_SE_P256_BYTES) || (size == NOXTLS_EFR32_SE_P384_BYTES)) ? 1U : 0U;
}

/**
 * @brief Keyspec of a plaintext Weierstrass key.
 * @internal
 *
 * @param[in] size  Coordinate bytes.
 * @param[in] flags NOXTLS_EFR32_KEYSPEC_ECC_PRIVATE and / or NOXTLS_EFR32_KEYSPEC_ECC_PUBLIC.
 *
 * @return Keyspec word.
 */
static uint32_t noxtls_efr32_ecc_keyspec(uint32_t size, uint32_t flags)
{
    return NOXTLS_EFR32_KEYSPEC_TYPE_WEIERSTRASS | flags | ((size - 1U) & NOXTLS_EFR32_KEYSPEC_ECC_SIZE_MSK);
}

/**
 * @brief Wipe all staging buffers.
 * @internal
 */
static void noxtls_efr32_ecc_wipe(void)
{
    noxtls_efr32_wipe(s_noxtls_efr32_ecc.key_buf, (uint32_t)sizeof(s_noxtls_efr32_ecc.key_buf));
    noxtls_efr32_wipe(s_noxtls_efr32_ecc.pub_buf, (uint32_t)sizeof(s_noxtls_efr32_ecc.pub_buf));
    noxtls_efr32_wipe(s_noxtls_efr32_ecc.msg_buf, (uint32_t)sizeof(s_noxtls_efr32_ecc.msg_buf));
    noxtls_efr32_wipe(s_noxtls_efr32_ecc.sig_buf, (uint32_t)sizeof(s_noxtls_efr32_ecc.sig_buf));
    noxtls_efr32_wipe(s_noxtls_efr32_ecc.out_buf, (uint32_t)sizeof(s_noxtls_efr32_ecc.out_buf));
}

/**
 * @brief Take the mailbox and prepare the empty authorization transfer.
 * @internal
 *
 * @return noxtls_efr32_se_acquire() result.
 */
static noxtls_return_t noxtls_efr32_ecc_begin(void)
{
    noxtls_return_t rc = noxtls_efr32_se_acquire();

    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_efr32_se_xfer_set(&s_noxtls_efr32_ecc.auth, NULL, 0U);
    }
    return rc;
}

/**
 * @brief Issue a command and translate failures for the caller.
 * @internal
 *
 * @param[in] cmd Command.
 *
 * @return As noxtls_efr32_se_run().
 */
static noxtls_return_t noxtls_efr32_ecc_run(const noxtls_efr32_se_cmd_t *cmd)
{
    return noxtls_efr32_se_run(cmd, (uint32_t)NOXTLS_EFR32_CONFIG_SE_PK_TIMEOUT_US);
}

noxtls_return_t noxtls_efr32_se_ecc_mul(uint32_t size, const uint8_t *scalar, const uint8_t *px, const uint8_t *py,
                                        uint8_t *rx, uint8_t *ry)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if ((scalar == NULL) || (px == NULL) || (py == NULL) || (rx == NULL) || (ry == NULL)) {
        rc = NOXTLS_RETURN_NULL;
    } else if (noxtls_efr32_ecc_size_ok(size) == 0U) {
        rc = NOXTLS_RETURN_INVALID_PARAM;
    } else if (noxtls_efr32_op_allowed(NOXTLS_EFR32_OP_ECC_MUL) == 0U) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    } else {
        rc = noxtls_efr32_ecc_begin();
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_efr32_se_cmd_t cmd;
        uint32_t attempt;

        (void)memcpy(s_noxtls_efr32_ecc.key_buf, scalar, size);
        (void)memcpy(s_noxtls_efr32_ecc.pub_buf, px, size);
        (void)memcpy(&s_noxtls_efr32_ecc.pub_buf[size], py, size);
        noxtls_efr32_se_xfer_set(&s_noxtls_efr32_ecc.key, s_noxtls_efr32_ecc.key_buf, size);
        noxtls_efr32_se_xfer_set(&s_noxtls_efr32_ecc.pub, s_noxtls_efr32_ecc.pub_buf, NOXTLS_EFR32_ECC_POINT_COORDS * size);
        noxtls_efr32_se_xfer_set(&s_noxtls_efr32_ecc.out, s_noxtls_efr32_ecc.out_buf, NOXTLS_EFR32_ECC_POINT_COORDS * size);
        noxtls_efr32_se_xfer_link(&s_noxtls_efr32_ecc.auth, &s_noxtls_efr32_ecc.key);
        noxtls_efr32_se_xfer_link(&s_noxtls_efr32_ecc.key, &s_noxtls_efr32_ecc.pub);
        (void)memset(&cmd, 0, sizeof(cmd));
        cmd.command = NOXTLS_EFR32_SE_CMD_DH;
        cmd.in = &s_noxtls_efr32_ecc.auth;
        cmd.out = &s_noxtls_efr32_ecc.out;
        cmd.params[0] = noxtls_efr32_ecc_keyspec(size, NOXTLS_EFR32_KEYSPEC_ECC_PRIVATE) & ~NOXTLS_EFR32_KEYSPEC_DH_RESERVED;
        cmd.params[1] = (NOXTLS_EFR32_ECC_POINT_COORDS * size) & NOXTLS_EFR32_KEYSPEC_RAW_SIZE_MSK;
        cmd.nparams = 2U;
        for (attempt = 0U; attempt < (uint32_t)NOXTLS_EFR32_CONFIG_SE_PTMUL_RETRIES; attempt++) {
            rc = noxtls_efr32_ecc_run(&cmd);
            if (rc != NOXTLS_RETURN_FAILED) {
                break;
            }
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            (void)memcpy(rx, s_noxtls_efr32_ecc.out_buf, size);
            (void)memcpy(ry, &s_noxtls_efr32_ecc.out_buf[size], size);
        } else {
            noxtls_efr32_wipe(rx, size);
            noxtls_efr32_wipe(ry, size);
        }
        noxtls_efr32_ecc_wipe();
        noxtls_efr32_se_release();
    }
    return rc;
}

noxtls_return_t noxtls_efr32_se_ecdsa_sign(uint32_t size, const uint8_t *d, const uint8_t *hash, uint8_t *r, uint8_t *s)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if ((d == NULL) || (hash == NULL) || (r == NULL) || (s == NULL)) {
        rc = NOXTLS_RETURN_NULL;
    } else if (noxtls_efr32_ecc_size_ok(size) == 0U) {
        rc = NOXTLS_RETURN_INVALID_PARAM;
    } else if (noxtls_efr32_op_allowed(NOXTLS_EFR32_OP_ECDSA_SIGN) == 0U) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    } else {
        rc = noxtls_efr32_ecc_begin();
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_efr32_se_cmd_t cmd;

        (void)memcpy(s_noxtls_efr32_ecc.key_buf, d, size);
        (void)memcpy(s_noxtls_efr32_ecc.msg_buf, hash, size);
        noxtls_efr32_se_xfer_set(&s_noxtls_efr32_ecc.key, s_noxtls_efr32_ecc.key_buf, size);
        noxtls_efr32_se_xfer_set(&s_noxtls_efr32_ecc.msg, s_noxtls_efr32_ecc.msg_buf, size);
        noxtls_efr32_se_xfer_set(&s_noxtls_efr32_ecc.out, s_noxtls_efr32_ecc.out_buf, NOXTLS_EFR32_ECC_POINT_COORDS * size);
        noxtls_efr32_se_xfer_link(&s_noxtls_efr32_ecc.auth, &s_noxtls_efr32_ecc.key);
        noxtls_efr32_se_xfer_link(&s_noxtls_efr32_ecc.key, &s_noxtls_efr32_ecc.msg);
        (void)memset(&cmd, 0, sizeof(cmd));
        cmd.command = NOXTLS_EFR32_SE_CMD_SIGN | NOXTLS_EFR32_SE_OPT_NONE;
        cmd.in = &s_noxtls_efr32_ecc.auth;
        cmd.out = &s_noxtls_efr32_ecc.out;
        cmd.params[0] = noxtls_efr32_ecc_keyspec(size, NOXTLS_EFR32_KEYSPEC_ECC_PRIVATE);
        cmd.params[1] = size;
        cmd.nparams = 2U;
        rc = noxtls_efr32_ecc_run(&cmd);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            (void)memcpy(r, s_noxtls_efr32_ecc.out_buf, size);
            (void)memcpy(s, &s_noxtls_efr32_ecc.out_buf[size], size);
        } else {
            noxtls_efr32_wipe(r, size);
            noxtls_efr32_wipe(s, size);
        }
        noxtls_efr32_ecc_wipe();
        noxtls_efr32_se_release();
    }
    return rc;
}

noxtls_return_t noxtls_efr32_se_ecdsa_verify(uint32_t size, const uint8_t *qx, const uint8_t *qy, const uint8_t *hash,
                                             const uint8_t *r, const uint8_t *s)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if ((qx == NULL) || (qy == NULL) || (hash == NULL) || (r == NULL) || (s == NULL)) {
        rc = NOXTLS_RETURN_NULL;
    } else if (noxtls_efr32_ecc_size_ok(size) == 0U) {
        rc = NOXTLS_RETURN_INVALID_PARAM;
    } else if (noxtls_efr32_op_allowed(NOXTLS_EFR32_OP_ECDSA_VERIFY) == 0U) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    } else {
        rc = noxtls_efr32_ecc_begin();
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_efr32_se_cmd_t cmd;

        (void)memcpy(s_noxtls_efr32_ecc.key_buf, qx, size);
        (void)memcpy(&s_noxtls_efr32_ecc.key_buf[size], qy, size);
        (void)memcpy(s_noxtls_efr32_ecc.msg_buf, hash, size);
        (void)memcpy(s_noxtls_efr32_ecc.sig_buf, r, size);
        (void)memcpy(&s_noxtls_efr32_ecc.sig_buf[size], s, size);
        noxtls_efr32_se_xfer_set(&s_noxtls_efr32_ecc.key, s_noxtls_efr32_ecc.key_buf, NOXTLS_EFR32_ECC_POINT_COORDS * size);
        noxtls_efr32_se_xfer_set(&s_noxtls_efr32_ecc.msg, s_noxtls_efr32_ecc.msg_buf, size);
        noxtls_efr32_se_xfer_set(&s_noxtls_efr32_ecc.sig, s_noxtls_efr32_ecc.sig_buf, NOXTLS_EFR32_ECC_POINT_COORDS * size);
        noxtls_efr32_se_xfer_link(&s_noxtls_efr32_ecc.auth, &s_noxtls_efr32_ecc.key);
        noxtls_efr32_se_xfer_link(&s_noxtls_efr32_ecc.key, &s_noxtls_efr32_ecc.msg);
        noxtls_efr32_se_xfer_link(&s_noxtls_efr32_ecc.msg, &s_noxtls_efr32_ecc.sig);
        (void)memset(&cmd, 0, sizeof(cmd));
        cmd.command = NOXTLS_EFR32_SE_CMD_VERIFY | NOXTLS_EFR32_SE_OPT_NONE;
        cmd.in = &s_noxtls_efr32_ecc.auth;
        cmd.params[0] = noxtls_efr32_ecc_keyspec(size, NOXTLS_EFR32_KEYSPEC_ECC_PUBLIC);
        cmd.params[1] = size;
        cmd.nparams = 2U;
        rc = noxtls_efr32_ecc_run(&cmd);
        noxtls_efr32_ecc_wipe();
        noxtls_efr32_se_release();
    }
    return rc;
}
