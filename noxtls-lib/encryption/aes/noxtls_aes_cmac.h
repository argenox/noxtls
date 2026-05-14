/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
* File:    noxtls_aes_cmac.h
* Summary: AES-CMAC (RFC 4493 / NIST SP 800-38B) for noxtls_message authentication.
*/

/** @addtogroup noxtls_encryption */

#ifndef _NOXTLS_AES_CMAC_H_
#define _NOXTLS_AES_CMAC_H_

#include <stdint.h>
#include "noxtls_aes.h"
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#if NOXTLS_FEATURE_AES_CMAC

/**
 * @brief Compute AES-CMAC over a noxtls_message (RFC 4493).
 *
 * Uses AES-128 only (key_len 16). Output is 16 bytes (full MAC).
 * For BLE Signed Write the caller may use only the first 12 bytes.
 *
 * @param key       AES key (16 bytes for AES-128)
 * @param msg       Message to authenticate
 * @param msg_len   Message length in bytes
 * @param mac       Output buffer for 16-byte MAC
 * @param type      AES key type (NOXTLS_AES_128_BIT recommended)
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t noxtls_aes_cmac(const uint8_t *key,
                         const uint8_t *msg,
                         uint32_t msg_len,
                         uint8_t *mac,
                         noxtls_aes_type_t type);

#endif /* NOXTLS_FEATURE_AES_CMAC */

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_AES_CMAC_H_ */
