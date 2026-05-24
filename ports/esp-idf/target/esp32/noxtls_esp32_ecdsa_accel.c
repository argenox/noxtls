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
* File:    noxtls_esp32_ecdsa_accel.c
* Summary: ESP-IDF ECDSA acceleration hook (pure-noxtls policy stub)
*
* Policy note:
* This port intentionally avoids calling mbedTLS ECDSA software routines.
* Only hardware-backed acceleration paths should be implemented here.
*
*
*****************************************************************************/

#include "noxtls_ecdsa_accel_port.h"

/**
 * @brief Sign the ECDSA signature.
 *
 * @param[in] key The key value.
 * @param[in] hash The hash value.
 * @param[in] hash_len The hash length value.
 * @param[out] signature The signature value.
 * @return The return value.
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
 * @brief Verify the ECDSA signature.
 *
 * @param[in] key The key value.
 * @param[in] hash The hash value.
 * @param[in] hash_len The hash length value.
 * @param[in] signature The signature value.
 * @return The return value.
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

