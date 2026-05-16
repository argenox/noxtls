/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_tls10.c
* Summary: TLS 1.0 Implementation (delegates to TLS 1.2 with version 1.0)
*
* TLS 1.0 uses MD5/SHA-1 PRF, implicit IV for CBC, and no extensions.
* The implementation reuses the TLS 1.2 code path with version TLS_VERSION_1_0.
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "noxtls_tls10.h"
#include "noxtls_tls12.h"
#include "noxtls_tls_common.h"

noxtls_return_t noxtls_tls10_context_init(tls10_context_t *ctx, tls_role_t role)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    return noxtls_tls12_context_init_with_version((tls12_context_t*)ctx, role, TLS_VERSION_1_0);
}

noxtls_return_t noxtls_tls10_context_free(tls10_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    return noxtls_tls12_context_free((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_connect(tls10_context_t *ctx)
{
    return noxtls_tls12_connect((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_accept(tls10_context_t *ctx)
{
    return noxtls_tls12_accept((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_send(tls10_context_t *ctx, const uint8_t *data, uint32_t len)
{
    return noxtls_tls12_send((tls12_context_t*)ctx, data, len);
}

noxtls_return_t noxtls_tls10_recv(tls10_context_t *ctx, uint8_t *data, uint32_t *len)
{
    return noxtls_tls12_recv((tls12_context_t*)ctx, data, len);
}

noxtls_return_t noxtls_tls10_close(tls10_context_t *ctx)
{
    return noxtls_tls12_close((tls12_context_t*)ctx);
}

/* Client handshake */
noxtls_return_t noxtls_tls10_send_client_hello(tls10_context_t *ctx)
{
    return noxtls_tls12_send_client_hello((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_recv_server_hello(tls10_context_t *ctx)
{
    return noxtls_tls12_recv_server_hello((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_recv_certificate(tls10_context_t *ctx)
{
    return noxtls_tls12_recv_certificate((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_recv_server_key_exchange(tls10_context_t *ctx)
{
    return noxtls_tls12_recv_server_key_exchange((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_recv_server_hello_done(tls10_context_t *ctx)
{
    return noxtls_tls12_recv_server_hello_done((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_send_client_key_exchange(tls10_context_t *ctx)
{
    return noxtls_tls12_send_client_key_exchange((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_send_change_cipher_spec(tls10_context_t *ctx)
{
    return noxtls_tls12_send_change_cipher_spec((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_send_finished(tls10_context_t *ctx)
{
    return noxtls_tls12_send_finished((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_recv_change_cipher_spec(tls10_context_t *ctx)
{
    return noxtls_tls12_recv_change_cipher_spec((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_recv_finished(tls10_context_t *ctx)
{
    return noxtls_tls12_recv_finished((tls12_context_t*)ctx);
}

/* Server handshake */
noxtls_return_t noxtls_tls10_recv_client_hello(tls10_context_t *ctx)
{
    return noxtls_tls12_recv_client_hello((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_send_server_hello(tls10_context_t *ctx)
{
    return noxtls_tls12_send_server_hello((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_send_certificate(tls10_context_t *ctx)
{
    return noxtls_tls12_send_certificate((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_send_server_key_exchange(tls10_context_t *ctx)
{
    return noxtls_tls12_send_server_key_exchange((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_send_server_hello_done(tls10_context_t *ctx)
{
    return noxtls_tls12_send_server_hello_done((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_recv_client_key_exchange(tls10_context_t *ctx)
{
    return noxtls_tls12_recv_client_key_exchange((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_recv_change_cipher_spec_client(tls10_context_t *ctx)
{
    return noxtls_tls12_recv_change_cipher_spec_client((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_recv_finished_client(tls10_context_t *ctx)
{
    return noxtls_tls12_recv_finished_client((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_send_change_cipher_spec_server(tls10_context_t *ctx)
{
    return noxtls_tls12_send_change_cipher_spec_server((tls12_context_t*)ctx);
}

noxtls_return_t noxtls_tls10_send_finished_server(tls10_context_t *ctx)
{
    return noxtls_tls12_send_finished_server((tls12_context_t*)ctx);
}
