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
* File:    noxtls_camellia_internal.h
* Summary: Internal Camellia Definitions (RFC 3713)
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */
/** @{ */

#ifndef _NOXTLS_CAMELLIA_INTERNAL_H_
#define _NOXTLS_CAMELLIA_INTERNAL_H_

#include <stdint.h>
#include "noxtls_camellia.h"
#include "noxtls_common.h"

/* Key schedule: kw[4], ke[6], k[24] (64-bit subkeys) */
noxtls_return_t noxtls_camellia_key_schedule(const uint8_t* key, uint64_t* kw, uint64_t* ke, uint64_t* k, noxtls_camellia_type_t type);

/* Block encrypt/decrypt (16-byte block) */
noxtls_return_t noxtls_camellia_encrypt_block_internal(const uint8_t* key, const uint8_t* data, uint8_t* output, noxtls_camellia_type_t type);
noxtls_return_t noxtls_camellia_decrypt_block_internal(const uint8_t* key, const uint8_t* data, uint8_t* output, noxtls_camellia_type_t type);

#endif /* _NOXTLS_CAMELLIA_INTERNAL_H_ */
