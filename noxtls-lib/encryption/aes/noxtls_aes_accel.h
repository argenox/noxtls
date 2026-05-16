/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_aes_accel.h
* Summary: Optional AES hardware acceleration backends
*
*/

#ifndef _NOXTLS_AES_ACCEL_H_
#define _NOXTLS_AES_ACCEL_H_

#include <stdint.h>

#include "noxtls_aes.h"
#include "noxtls_common.h"

noxtls_return_t noxtls_aes_accel_ni_encrypt_block(const uint8_t *key,
                                                   const uint8_t *data,
                                                   uint8_t *output,
                                                   noxtls_aes_type_t type);
noxtls_return_t noxtls_aes_accel_ni_decrypt_block(const uint8_t *key,
                                                   const uint8_t *data,
                                                   uint8_t *output,
                                                   noxtls_aes_type_t type);
noxtls_return_t noxtls_aes_accel_apple_encrypt_block(const uint8_t *key,
                                                      const uint8_t *data,
                                                      uint8_t *output,
                                                      noxtls_aes_type_t type);
noxtls_return_t noxtls_aes_accel_apple_decrypt_block(const uint8_t *key,
                                                      const uint8_t *data,
                                                      uint8_t *output,
                                                      noxtls_aes_type_t type);

#endif /* _NOXTLS_AES_ACCEL_H_ */
