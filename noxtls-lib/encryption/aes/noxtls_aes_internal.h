/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
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

typedef enum
{
    NOXTLS_AES_ACCEL_BACKEND_SOFTWARE = 0,
    NOXTLS_AES_ACCEL_BACKEND_NI = 1,
    NOXTLS_AES_ACCEL_BACKEND_APPLE = 2,
    NOXTLS_AES_ACCEL_BACKEND_STM32 = 3
} noxtls_aes_accel_backend_t;

/* Internal function to encrypt a single AES block */
noxtls_return_t noxtls_aes_encrypt_block_internal(const uint8_t* key, const uint8_t* data, uint8_t* output, noxtls_aes_type_t type);

/* Internal function to decrypt a single AES block */
noxtls_return_t noxtls_aes_decrypt_block_internal(const uint8_t* key, const uint8_t* data, uint8_t* output, noxtls_aes_type_t type);

/* Report which AES block backend is compiled as active for this target. */
noxtls_aes_accel_backend_t noxtls_aes_get_accel_backend(void);

#endif /* _AES_INTERNAL_H_ */
