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
* Summary: TLS 1.1 Definitions
*
* Note: TLS1.1 is deprecated and should not be used for new deployments.
*       It is left here for legacy reasons but won't be supported
*
*****************************************************************************/

#ifndef _NOXTLS_TLS11_H_
#define _NOXTLS_TLS11_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_tls_common.h"
#include "noxtls_tls12.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TLS 1.1 Context: same as TLS 1.2 context (use noxtls_tls12_context_init_with_version for TLS 1.1) */
typedef tls12_context_t tls11_context_t;

/* TLS 1.1 Functions */
noxtls_return_t noxtls_tls11_context_init(tls11_context_t *ctx, tls_role_t role);
noxtls_return_t noxtls_tls11_context_free(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_connect(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_accept(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_send(tls11_context_t *ctx, const uint8_t *data, uint32_t len);
noxtls_return_t noxtls_tls11_recv(tls11_context_t *ctx, uint8_t *data, uint32_t *len);
noxtls_return_t noxtls_tls11_close(tls11_context_t *ctx);

/* TLS 1.1 Client Handshake Functions */
noxtls_return_t noxtls_tls11_send_client_hello(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_recv_server_hello(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_recv_certificate(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_recv_server_key_exchange(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_recv_server_hello_done(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_send_client_key_exchange(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_send_change_cipher_spec(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_send_finished(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_recv_change_cipher_spec(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_recv_finished(tls11_context_t *ctx);

/* TLS 1.1 Server Handshake Functions */
noxtls_return_t noxtls_tls11_recv_client_hello(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_send_server_hello(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_send_certificate(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_send_server_key_exchange(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_send_server_hello_done(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_recv_client_key_exchange(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_recv_change_cipher_spec_client(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_recv_finished_client(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_send_change_cipher_spec_server(tls11_context_t *ctx);
noxtls_return_t noxtls_tls11_send_finished_server(tls11_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_TLS11_H_ */


