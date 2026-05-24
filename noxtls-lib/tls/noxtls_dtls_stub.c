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
* File:    noxtls_dtls_stub.c
* Summary: DTLS Stub Implementation
*
* Minimal dtls_context_t init/free when BUILD_DTLS=OFF (NOXTLS_FEATURE_DTLS disabled).
* TLS 1.2/1.3 use dtls_context_t as their base structure; DTLS record/cookie APIs are
* compiled out of the TLS sources with #if NOXTLS_FEATURE_DTLS.
*
*****************************************************************************/

#include <string.h>
#include "noxtls_dtls_common.h"

/**
 * @brief Initialize the DTLS context.
 *
 * @param[in] ctx The context value.
 * @param[in] role The role value.
 * @param[in] version The version value.
 * @return The return value.
 */
noxtls_return_t noxtls_dtls_context_init(dtls_context_t *ctx, tls_role_t role, uint16_t version)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    memset(ctx, 0, sizeof(dtls_context_t));
    if(noxtls_tls_context_init(&ctx->base, role, version) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Free the DTLS context.
 *
 * @param[in] ctx The context value.
 * @return The return value.
 */
noxtls_return_t noxtls_dtls_context_free(dtls_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_tls_context_free(&ctx->base);
    memset(ctx, 0, sizeof(dtls_context_t));
    return NOXTLS_RETURN_SUCCESS;
}
