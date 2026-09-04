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
* File:    noxtls_aes_gcm.h
* Summary: AES-GCM mode implementation
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */
/** @{ */

#ifndef NOXTLS_AES_GCM_H_
#define NOXTLS_AES_GCM_H_

#include <stdint.h>
#include "noxtls_aes.h"
#include "noxtls_common.h"

noxtls_return_t noxtls_aes_gcm_encrypt(const uint8_t *key, noxtls_aes_type_t type,
                    const uint8_t *nonce,
                    const uint8_t *aad, uint32_t aad_len,
                    const uint8_t *plaintext, uint32_t plaintext_len,
                    uint8_t *ciphertext,
                    uint8_t *tag);

noxtls_return_t noxtls_aes_gcm_decrypt(const uint8_t *key, noxtls_aes_type_t type,
                    const uint8_t *nonce,
                    const uint8_t *aad, uint32_t aad_len,
                    const uint8_t *ciphertext, uint32_t ciphertext_len,
                    const uint8_t *tag,
                    uint8_t *plaintext);

#endif /* NOXTLS_AES_GCM_H_ */
