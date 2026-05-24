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
* File:    noxtls_ecdsa_accel_port.c
* Summary: Default (stub) ECDSA acceleration hook
*
*
*****************************************************************************/

#include "noxtls_ecdsa_accel_port.h"

/**
 * @brief Sign the message using the acceleration port
 *
 * @param[in] key The key to sign the message with
 * @param[in] hash The hash of the message to sign
 * @param[in] hash_len The length of the hash of the message to sign
 * @param[out] signature The signature to sign the message into
 * @return The return code
 */
noxtls_return_t noxtls_ecdsa_sign_accel_port(const ecc_key_t *key,
                                             const uint8_t *hash,
                                             uint32_t hash_len,
                                             ecdsa_signature_t *signature)
{
    (void)key;
    (void)hash;
    (void)hash_len;
    (void)signature;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

/**
 * @brief Verify the message using the acceleration port
 *
 * @param[in] key The key to verify the message with
 * @param[in] hash The hash of the message to verify
 * @param[in] hash_len The length of the hash of the message to verify
 * @param[in] signature The signature to verify the message with
 * @return The return code
 */
noxtls_return_t noxtls_ecdsa_verify_accel_port(const ecc_key_t *key,
                                               const uint8_t *hash,
                                               uint32_t hash_len,
                                               const ecdsa_signature_t *signature)
{
    (void)key;
    (void)hash;
    (void)hash_len;
    (void)signature;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

