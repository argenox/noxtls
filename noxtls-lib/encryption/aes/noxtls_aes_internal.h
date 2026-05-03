/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
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
*
* File:    noxtls_aes_internal.h
* Summary: Internal AES functions for mode implementations
*
*/

/** @addtogroup noxtls_encryption */
/** @{ */

#ifndef _AES_INTERNAL_H_
#define _AES_INTERNAL_H_

#include <stdint.h>
#include "noxtls_aes.h"
#include "noxtls_common.h"

/* Internal function to encrypt a single AES block */
noxtls_return_t aes_encrypt_block_internal(const uint8_t* key, const uint8_t* data, uint8_t* output, aes_type_t type);

/* Internal function to decrypt a single AES block */
noxtls_return_t aes_decrypt_block_internal(const uint8_t* key, const uint8_t* data, uint8_t* output, aes_type_t type);

#endif /* _AES_INTERNAL_H_ */

