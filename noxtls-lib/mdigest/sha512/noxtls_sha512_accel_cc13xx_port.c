/*****************************************************************************
 * Copyright (c) 2026, Argenox Technologies LLC. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
 *****************************************************************************/
/** @file noxtls_sha512_accel_cc13xx_port.c
 * @brief Optional application-owned SHA-384/512 block compression.
 */
#include <stddef.h>
#include "noxtls_sha512.h"
#include "common/noxtls_cc13xx_crypto.h"

/** @copydoc noxtls_sha512_blocks_accel_port */
noxtls_return_t noxtls_sha512_blocks_accel_port(noxtls_sha512_ctx_t *ctx,
    const uint8_t *input, uint32_t blocks)
{
    return ctx != NULL ? noxtls_cc13xx_sha512_blocks(ctx->h,input,blocks) : NOXTLS_RETURN_NULL;
}
