/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* NOTICE:  All information contained herein, source code, binaries and
* derived works is, and remains
* the property of Argenox Technologies and its suppliers,
* if any.  The intellectual and technical concepts contained
* herein are proprietary to Argenox Technologies
* and its suppliers may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Argenox Technologies.
*
* THIS SOFTWARE IS PROVIDED BY ARGENOX "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ARGENOX TECHNOLOGIES LLC BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_tls11.h
* Summary: TLS 1.1 Implementation
*
*/

#ifndef _NOXTLS_TLS11_H_
#define _NOXTLS_TLS11_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_tls_common.h"
#include "noxtls_tls12.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TLS 1.1 Context: same as TLS 1.2 context (use tls12_context_init_with_version for TLS 1.1) */
typedef tls12_context_t tls11_context_t;

/* TLS 1.1 Functions */
noxtls_return_t tls11_context_init(tls11_context_t *ctx, tls_role_t role);
noxtls_return_t tls11_context_free(tls11_context_t *ctx);
noxtls_return_t tls11_connect(tls11_context_t *ctx);
noxtls_return_t tls11_accept(tls11_context_t *ctx);
noxtls_return_t tls11_send(tls11_context_t *ctx, const uint8_t *data, uint32_t len);
noxtls_return_t tls11_recv(tls11_context_t *ctx, uint8_t *data, uint32_t *len);
noxtls_return_t tls11_close(tls11_context_t *ctx);

/* TLS 1.1 Client Handshake Functions */
noxtls_return_t tls11_send_client_hello(tls11_context_t *ctx);
noxtls_return_t tls11_recv_server_hello(tls11_context_t *ctx);
noxtls_return_t tls11_recv_certificate(tls11_context_t *ctx);
noxtls_return_t tls11_recv_server_key_exchange(tls11_context_t *ctx);
noxtls_return_t tls11_recv_server_hello_done(tls11_context_t *ctx);
noxtls_return_t tls11_send_client_key_exchange(tls11_context_t *ctx);
noxtls_return_t tls11_send_change_cipher_spec(tls11_context_t *ctx);
noxtls_return_t tls11_send_finished(tls11_context_t *ctx);
noxtls_return_t tls11_recv_change_cipher_spec(tls11_context_t *ctx);
noxtls_return_t tls11_recv_finished(tls11_context_t *ctx);

/* TLS 1.1 Server Handshake Functions */
noxtls_return_t tls11_recv_client_hello(tls11_context_t *ctx);
noxtls_return_t tls11_send_server_hello(tls11_context_t *ctx);
noxtls_return_t tls11_send_certificate(tls11_context_t *ctx);
noxtls_return_t tls11_send_server_key_exchange(tls11_context_t *ctx);
noxtls_return_t tls11_send_server_hello_done(tls11_context_t *ctx);
noxtls_return_t tls11_recv_client_key_exchange(tls11_context_t *ctx);
noxtls_return_t tls11_recv_change_cipher_spec_client(tls11_context_t *ctx);
noxtls_return_t tls11_recv_finished_client(tls11_context_t *ctx);
noxtls_return_t tls11_send_change_cipher_spec_server(tls11_context_t *ctx);
noxtls_return_t tls11_send_finished_server(tls11_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_TLS11_H_ */


