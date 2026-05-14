/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* Stub implementations when BUILD_DTLS=OFF so TLS 1.2 context (which uses
* dtls_context_t as base) still links. Full DTLS logic is in noxtls_dtls_common.c.
*****************************************************************************/

#include <string.h>
#include "noxtls_dtls_common.h"

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

noxtls_return_t noxtls_dtls_context_free(dtls_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_tls_context_free(&ctx->base);
    memset(ctx, 0, sizeof(dtls_context_t));
    return NOXTLS_RETURN_SUCCESS;
}
