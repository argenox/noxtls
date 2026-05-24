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
* File:    noxtls_des_internal.h
* Summary: Internal DES block functions for mode implementations
*
* The DES and 3DES Algorithms are broken and should not be used for new systems.
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */
/** @{ */

#ifndef _NOXTLS_DES_INTERNAL_H_
#define _NOXTLS_DES_INTERNAL_H_

#include <stdint.h>
#include "noxtls_des.h"
#include "noxtls_common.h"

/* Single-block encrypt/decrypt for use by CBC etc. */
noxtls_return_t noxtls_des_encrypt_block_internal(const uint8_t *key, const uint8_t *data, uint8_t *output);
noxtls_return_t noxtls_des_decrypt_block_internal(const uint8_t *key, const uint8_t *data, uint8_t *output);

#endif /* _NOXTLS_DES_INTERNAL_H_ */
/** @} */