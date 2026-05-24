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
* File:    noxtls_sha256_accel_port.c
* Summary: Platform SHA-224/256 acceleration hook (default fallback)
*
*
*****************************************************************************/


#include <stdint.h>

#include "noxtls_sha.h"
#include "noxtls_common.h"

/**
 * @brief SHA-256 round acceleration port
 * 
 * @param ctx The SHA-256 context
 * @param input The input data
 * @return The return value
 */
noxtls_return_t noxtls_sha256_round_accel_port(noxtls_sha_ctx_t *ctx, const uint8_t *input)
{
    (void)ctx;
    (void)input;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

/**
 * @brief SHA-256 blocks acceleration port
 * 
 * @param ctx The SHA-256 context
 * @param input The input data
 * @param block_count The number of blocks
 * @return The return value
 */
noxtls_return_t noxtls_sha256_blocks_accel_port(noxtls_sha_ctx_t *ctx, const uint8_t *input, uint32_t block_count)
{
    (void)ctx;
    (void)input;
    (void)block_count;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}
