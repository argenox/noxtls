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
* File:    noxtls_sha256_accel_port.h
* Summary: SHA-224/256 platform acceleration port declarations
*
*****************************************************************************/

#ifndef NOXTLS_SHA256_ACCEL_PORT_H
#define NOXTLS_SHA256_ACCEL_PORT_H

#include <stdint.h>
#include "noxtls_sha.h"
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

noxtls_return_t noxtls_sha256_round_accel_port(noxtls_sha_ctx_t *ctx, const uint8_t *input);
noxtls_return_t noxtls_sha256_blocks_accel_port(noxtls_sha_ctx_t *ctx, const uint8_t *input, uint32_t block_count);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_SHA256_ACCEL_PORT_H */
