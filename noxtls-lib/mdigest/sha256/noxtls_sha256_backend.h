/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_sha256_backend.h
* Summary: Internal SHA-256 software backend diagnostics and controls.
*
*****************************************************************************/

#ifndef _NOXTLS_SHA256_BACKEND_H_
#define _NOXTLS_SHA256_BACKEND_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_sha.h"

const char *noxtls_sha256_backend_name(void);
uint8_t noxtls_sha256_backend_is_cortexm7(void);
void noxtls_sha256_backend_set_cortexm7_enabled(uint8_t enabled);
noxtls_return_t noxtls_sha256_blocks_cortexm7(noxtls_sha_ctx_t *ctx,
                                              const uint8_t *input,
                                              uint32_t block_count);

#endif /* _NOXTLS_SHA256_BACKEND_H_ */
