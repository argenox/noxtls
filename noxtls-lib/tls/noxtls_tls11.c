/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_tls11.c
* Summary: TLS 1.1 Implementation (delegates to TLS 1.2 with version 1.1)
*
* TLS 1.1 uses MD5/SHA-1 PRF and explicit IV per record for CBC.
* The implementation reuses the TLS 1.2 code path with version TLS_VERSION_1_1.
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "noxtls_tls11.h"
#include "noxtls_tls12.h"
#include "noxtls_tls_common.h"

noxtls_return_t tls11_context_init(tls11_context_t *ctx, tls_role_t role)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    return tls12_context_init_with_version((tls12_context_t*)ctx, role, TLS_VERSION_1_1);
}

noxtls_return_t tls11_context_free(tls11_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    return tls12_context_free((tls12_context_t*)ctx);
}

noxtls_return_t tls11_connect(tls11_context_t *ctx)
{
    return tls12_connect((tls12_context_t*)ctx);
}

noxtls_return_t tls11_accept(tls11_context_t *ctx)
{
    return tls12_accept((tls12_context_t*)ctx);
}

noxtls_return_t tls11_send(tls11_context_t *ctx, const uint8_t *data, uint32_t len)
{
    return tls12_send((tls12_context_t*)ctx, data, len);
}

noxtls_return_t tls11_recv(tls11_context_t *ctx, uint8_t *data, uint32_t *len)
{
    return tls12_recv((tls12_context_t*)ctx, data, len);
}

noxtls_return_t tls11_close(tls11_context_t *ctx)
{
    return tls12_close((tls12_context_t*)ctx);
}

/* Client handshake */
noxtls_return_t tls11_send_client_hello(tls11_context_t *ctx)
{
    return tls12_send_client_hello((tls12_context_t*)ctx);
}

noxtls_return_t tls11_recv_server_hello(tls11_context_t *ctx)
{
    return tls12_recv_server_hello((tls12_context_t*)ctx);
}

noxtls_return_t tls11_recv_certificate(tls11_context_t *ctx)
{
    return tls12_recv_certificate((tls12_context_t*)ctx);
}

noxtls_return_t tls11_recv_server_key_exchange(tls11_context_t *ctx)
{
    return tls12_recv_server_key_exchange((tls12_context_t*)ctx);
}

noxtls_return_t tls11_recv_server_hello_done(tls11_context_t *ctx)
{
    return tls12_recv_server_hello_done((tls12_context_t*)ctx);
}

noxtls_return_t tls11_send_client_key_exchange(tls11_context_t *ctx)
{
    return tls12_send_client_key_exchange((tls12_context_t*)ctx);
}

noxtls_return_t tls11_send_change_cipher_spec(tls11_context_t *ctx)
{
    return tls12_send_change_cipher_spec((tls12_context_t*)ctx);
}

noxtls_return_t tls11_send_finished(tls11_context_t *ctx)
{
    return tls12_send_finished((tls12_context_t*)ctx);
}

noxtls_return_t tls11_recv_change_cipher_spec(tls11_context_t *ctx)
{
    return tls12_recv_change_cipher_spec((tls12_context_t*)ctx);
}

noxtls_return_t tls11_recv_finished(tls11_context_t *ctx)
{
    return tls12_recv_finished((tls12_context_t*)ctx);
}

/* Server handshake */
noxtls_return_t tls11_recv_client_hello(tls11_context_t *ctx)
{
    return tls12_recv_client_hello((tls12_context_t*)ctx);
}

noxtls_return_t tls11_send_server_hello(tls11_context_t *ctx)
{
    return tls12_send_server_hello((tls12_context_t*)ctx);
}

noxtls_return_t tls11_send_certificate(tls11_context_t *ctx)
{
    return tls12_send_certificate((tls12_context_t*)ctx);
}

noxtls_return_t tls11_send_server_key_exchange(tls11_context_t *ctx)
{
    return tls12_send_server_key_exchange((tls12_context_t*)ctx);
}

noxtls_return_t tls11_send_server_hello_done(tls11_context_t *ctx)
{
    return tls12_send_server_hello_done((tls12_context_t*)ctx);
}

noxtls_return_t tls11_recv_client_key_exchange(tls11_context_t *ctx)
{
    return tls12_recv_client_key_exchange((tls12_context_t*)ctx);
}

noxtls_return_t tls11_recv_change_cipher_spec_client(tls11_context_t *ctx)
{
    return tls12_recv_change_cipher_spec_client((tls12_context_t*)ctx);
}

noxtls_return_t tls11_recv_finished_client(tls11_context_t *ctx)
{
    return tls12_recv_finished_client((tls12_context_t*)ctx);
}

noxtls_return_t tls11_send_change_cipher_spec_server(tls11_context_t *ctx)
{
    return tls12_send_change_cipher_spec_server((tls12_context_t*)ctx);
}

noxtls_return_t tls11_send_finished_server(tls11_context_t *ctx)
{
    return tls12_send_finished_server((tls12_context_t*)ctx);
}
