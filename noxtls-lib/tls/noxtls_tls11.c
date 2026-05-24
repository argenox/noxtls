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
* File:    noxtls_tls11.c
* Summary: TLS 1.1 Implementation (delegates to TLS 1.2 with version 1.1)
*
* Note: TLS1.1 is deprecated and should not be used for new deployments.
*       It is left here for legacy reasons but won't be supported
*
* TLS 1.1 uses MD5/SHA-1 PRF and explicit IV per record for CBC.
* The implementation reuses the TLS 1.2 code path with version TLS_VERSION_1_1.
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "noxtls_tls11.h"
#include "noxtls_tls12.h"
#include "noxtls_tls_common.h"

/**
 * @brief Initialize a TLS 1.1 context
 *
 * @param[in] ctx The context to initialize
 * @param[in] role The role of the context
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_context_init(tls11_context_t *ctx, tls_role_t role)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    return noxtls_tls12_context_init_with_version((tls12_context_t*)ctx, role, TLS_VERSION_1_1);
}

/**
 * @brief Free a TLS 1.1 context
 *
 * @param[in] ctx The context to free
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_context_free(tls11_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    return noxtls_tls12_context_free((tls12_context_t*)ctx);
}

/**
 * @brief Connect a TLS 1.1 context
 *
 * @param[in] ctx The context to connect
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_connect(tls11_context_t *ctx)
{
    return noxtls_tls12_connect((tls12_context_t*)ctx);
}

/**
 * @brief Accept a TLS 1.1 context
 *
 * @param[in] ctx The context to accept
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_accept(tls11_context_t *ctx)
{
    return noxtls_tls12_accept((tls12_context_t*)ctx);
}

/**
 * @brief Send data over a TLS 1.1 context
 *
 * @param[in] ctx The context to send data over
 * @param[in] data The data to send
 * @param[in] len The length of the data to send
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_send(tls11_context_t *ctx, const uint8_t *data, uint32_t len)
{
    return noxtls_tls12_send((tls12_context_t*)ctx, data, len);
}

/**
 * @brief Receive data over a TLS 1.1 context
 *
 * @param[in] ctx The context to receive data over
 * @param[out] data The data to receive
 * @param[out] len The length of the data received
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_recv(tls11_context_t *ctx, uint8_t *data, uint32_t *len)
{
    return noxtls_tls12_recv((tls12_context_t*)ctx, data, len);
}

/**
 * @brief Close a TLS 1.1 context
 *
 * @param[in] ctx The context to close
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_close(tls11_context_t *ctx)
{
    return noxtls_tls12_close((tls12_context_t*)ctx);
}

/* Client handshake */
/**
 * @brief Send a client hello over a TLS 1.1 context
 *
 * @param[in] ctx The context to send a client hello over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_send_client_hello(tls11_context_t *ctx)
{
    return noxtls_tls12_send_client_hello((tls12_context_t*)ctx);
}

/**
 * @brief Receive a server hello over a TLS 1.1 context
 *
 * @param[in] ctx The context to receive a server hello over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_recv_server_hello(tls11_context_t *ctx)
{
    return noxtls_tls12_recv_server_hello((tls12_context_t*)ctx);
}

/**
 * @brief Receive a certificate over a TLS 1.1 context
 *
 * @param[in] ctx The context to receive a certificate over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_recv_certificate(tls11_context_t *ctx)
{
    return noxtls_tls12_recv_certificate((tls12_context_t*)ctx);
}

/**
 * @brief Receive a server key exchange over a TLS 1.1 context
 *
 * @param[in] ctx The context to receive a server key exchange over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_recv_server_key_exchange(tls11_context_t *ctx)
{
    return noxtls_tls12_recv_server_key_exchange((tls12_context_t*)ctx);
}

/**
 * @brief Receive a server hello done over a TLS 1.1 context
 *
 * @param[in] ctx The context to receive a server hello done over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_recv_server_hello_done(tls11_context_t *ctx)
{
    return noxtls_tls12_recv_server_hello_done((tls12_context_t*)ctx);
}

/**
 * @brief Send a client key exchange over a TLS 1.1 context
 *
 * @param[in] ctx The context to send a client key exchange over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_send_client_key_exchange(tls11_context_t *ctx)
{
    return noxtls_tls12_send_client_key_exchange((tls12_context_t*)ctx);
}

/**
 * @brief Send a change cipher spec over a TLS 1.1 context
 *
 * @param[in] ctx The context to send a change cipher spec over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_send_change_cipher_spec(tls11_context_t *ctx)
{
    return noxtls_tls12_send_change_cipher_spec((tls12_context_t*)ctx);
}

/**
 * @brief Send a finished over a TLS 1.1 context
 *
 * @param[in] ctx The context to send a finished over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_send_finished(tls11_context_t *ctx)
{
    return noxtls_tls12_send_finished((tls12_context_t*)ctx);
}

/**
 * @brief Receive a change cipher spec over a TLS 1.1 context
 *
 * @param[in] ctx The context to receive a change cipher spec over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_recv_change_cipher_spec(tls11_context_t *ctx)
{
    return noxtls_tls12_recv_change_cipher_spec((tls12_context_t*)ctx);
}

/**
 * @brief Receive a finished over a TLS 1.1 context
 *
 * @param[in] ctx The context to receive a finished over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_recv_finished(tls11_context_t *ctx)
{
    return noxtls_tls12_recv_finished((tls12_context_t*)ctx);
}

/* Server handshake */
/**
 * @brief Receive a client hello over a TLS 1.1 context
 *
 * @param[in] ctx The context to receive a client hello over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_recv_client_hello(tls11_context_t *ctx)
{
    return noxtls_tls12_recv_client_hello((tls12_context_t*)ctx);
}

/**
 * @brief Send a server hello over a TLS 1.1 context
 *
 * @param[in] ctx The context to send a server hello over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_send_server_hello(tls11_context_t *ctx)
{
    return noxtls_tls12_send_server_hello((tls12_context_t*)ctx);
}

/**
 * @brief Send a certificate over a TLS 1.1 context
 *
 * @param[in] ctx The context to send a certificate over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_send_certificate(tls11_context_t *ctx)
{
    return noxtls_tls12_send_certificate((tls12_context_t*)ctx);
}

/**
 * @brief Send a server key exchange over a TLS 1.1 context
 *
 * @param[in] ctx The context to send a server key exchange over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_send_server_key_exchange(tls11_context_t *ctx)
{
    return noxtls_tls12_send_server_key_exchange((tls12_context_t*)ctx);
}

/**
 * @brief Send a server hello done over a TLS 1.1 context
 *
 * @param[in] ctx The context to send a server hello done over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_send_server_hello_done(tls11_context_t *ctx)
{
    return noxtls_tls12_send_server_hello_done((tls12_context_t*)ctx);
}

/**
 * @brief Receive a client key exchange over a TLS 1.1 context
 *
 * @param[in] ctx The context to receive a client key exchange over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_recv_client_key_exchange(tls11_context_t *ctx)
{
    return noxtls_tls12_recv_client_key_exchange((tls12_context_t*)ctx);
}

/**
 * @brief Receive a change cipher spec over a TLS 1.1 context
 *
 * @param[in] ctx The context to receive a change cipher spec over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_recv_change_cipher_spec_client(tls11_context_t *ctx)
{
    return noxtls_tls12_recv_change_cipher_spec_client((tls12_context_t*)ctx);
}

/**
 * @brief Receive a finished over a TLS 1.1 context
 *
 * @param[in] ctx The context to receive a finished over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_recv_finished_client(tls11_context_t *ctx)
{
    return noxtls_tls12_recv_finished_client((tls12_context_t*)ctx);
}

/**
 * @brief Send a change cipher spec over a TLS 1.1 context
 *
 * @param[in] ctx The context to send a change cipher spec over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_send_change_cipher_spec_server(tls11_context_t *ctx)
{
    return noxtls_tls12_send_change_cipher_spec_server((tls12_context_t*)ctx);
}

/**
 * @brief Send a finished over a TLS 1.1 context
 *
 * @param[in] ctx The context to send a finished over
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_tls11_send_finished_server(tls11_context_t *ctx)
{
    return noxtls_tls12_send_finished_server((tls12_context_t*)ctx);
}
