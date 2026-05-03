/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_des_internal.h
* Summary: Internal DES block functions for mode implementations
*
*/

#ifndef _NOXTLS_DES_INTERNAL_H_
#define _NOXTLS_DES_INTERNAL_H_

#include <stdint.h>
#include "noxtls_des.h"
#include "noxtls_common.h"

/* Single-block encrypt/decrypt for use by CBC etc. */
noxtls_return_t des_encrypt_block_internal(const uint8_t *key, const uint8_t *data, uint8_t *output);
noxtls_return_t des_decrypt_block_internal(const uint8_t *key, const uint8_t *data, uint8_t *output);

#endif /* _NOXTLS_DES_INTERNAL_H_ */
