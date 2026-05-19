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
* This file is part of the NoxTLS Library.
*
* File:    noxtls_tls_auto.c
* Summary: TLS Automatic Version Negotiation
*
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "noxtls_tls_common.h"
#if NOXTLS_FEATURE_TLS10
#include "noxtls_tls10.h"
#endif
#if NOXTLS_FEATURE_TLS11
#include "noxtls_tls11.h"
#endif
#include "noxtls_tls12.h"
#include "noxtls_tls13.h"

/**
 * @brief Unified TLS Accept with Automatic Version Negotiation
 * 
 * This function automatically detects the TLS version requested by the client
 * by examining the Client Hello noxtls_message, then routes to the appropriate
 * version-specific accept function.
 * 
 * @param base_ctx Base TLS context with I/O callbacks set (must be server role)
 * @param tls10_ctx TLS 1.0 context (must be initialized with noxtls_tls10_context_init, can be NULL)
 * @param tls11_ctx TLS 1.1 context (must be initialized with noxtls_tls11_context_init, can be NULL)
 * @param tls12_ctx TLS 1.2 context (must be initialized with noxtls_tls12_context_init)
 * @param tls13_ctx TLS 1.3 context (initialized with noxtls_tls13_context_init), or NULL to
 *                  act as a TLS-1.3-disabled server: if the client offers TLS 1.2 in
 *                  supported_versions, negotiation falls back to TLS 1.2 instead of 1.3.
 * @param negotiated_version Output: The negotiated TLS version
 * @return NOXTLS_RETURN_SUCCESS on success, error code on failure
 */
noxtls_return_t tls_accept_auto(tls_context_t *base_ctx,
                                   void *tls10_ctx, /* NOLINT(bugprone-easily-swappable-parameters): optional context slots are ordered by TLS version. */
                                   void *tls11_ctx,
                                   tls12_context_t *tls12_ctx,
                                   tls13_context_t *tls13_ctx,
                                   uint16_t *negotiated_version)
{
    noxtls_return_t rc;
    uint16_t detected_version;

    (void)tls10_ctx;
    (void)tls11_ctx;
    uint8_t *client_hello_data = NULL;
    uint32_t client_hello_len = 0;
    
    if(base_ctx == NULL || tls12_ctx == NULL || negotiated_version == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(base_ctx->role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }

    /* I/O callbacks are required for version detection (recv Client Hello) */
    if(base_ctx->recv_callback == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Detect TLS version from Client Hello */
    rc = noxtls_tls_detect_version(base_ctx, &detected_version, &client_hello_data, &client_hello_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        if(base_ctx->send_callback != NULL) {
            uint8_t alert_desc = TLS_ALERT_HANDSHAKE_FAILURE;
            if(rc == NOXTLS_RETURN_NOT_SUPPORTED) {
                alert_desc = TLS_ALERT_PROTOCOL_VERSION;
            } else if(rc == NOXTLS_RETURN_TLS_ERROR) {
                alert_desc = TLS_ALERT_UNEXPECTED_MESSAGE;
            } else if(rc == NOXTLS_RETURN_BAD_DATA) {
                alert_desc = TLS_ALERT_DECODE_ERROR;
            } else if(rc == NOXTLS_RETURN_RECORD_OVERFLOW) {
                alert_desc = TLS_ALERT_RECORD_OVERFLOW;
            } else if(rc == NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER) {
                alert_desc = TLS_ALERT_ILLEGAL_PARAMETER;
            } else if(rc == NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR) {
                alert_desc = TLS_ALERT_DECODE_ERROR;
            }
            (void)noxtls_tls_send_alert(base_ctx, TLS_ALERT_LEVEL_FATAL, alert_desc);
        }
        return rc;
    }
    
    /* Store Client Hello in the appropriate context for later use. */
    // NOLINTNEXTLINE(bugprone-branch-clone): TLS 1.0 and 1.1 flows intentionally mirror setup/cleanup with version-specific accept calls.
    if(detected_version == TLS_VERSION_1_0) {
#if NOXTLS_FEATURE_TLS10
        /* TLS 1.0 */
        if(tls10_ctx == NULL) {
            if(base_ctx->send_callback != NULL) {
                (void)noxtls_tls_send_alert(base_ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_PROTOCOL_VERSION);
            }
            if(client_hello_data) noxtls_free(client_hello_data);
            return NOXTLS_RETURN_NOT_SUPPORTED;  /* TLS 1.0 context not provided */
        }
        tls10_context_t *tls10 = (tls10_context_t*)tls10_ctx;
        tls10->base.base.pending_client_hello = client_hello_data;
        tls10->base.base.pending_client_hello_len = client_hello_len;
        tls10->base.base.send_callback = base_ctx->send_callback;
        tls10->base.base.recv_callback = base_ctx->recv_callback;
        tls10->base.base.user_data = base_ctx->user_data;
        tls10->base.base.io_mode = base_ctx->io_mode;
        rc = noxtls_tls10_accept(tls10);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            *negotiated_version = TLS_VERSION_1_0;
        }
        if(tls10->base.base.pending_client_hello) {
            noxtls_free(tls10->base.base.pending_client_hello);
            tls10->base.base.pending_client_hello = NULL;
            tls10->base.base.pending_client_hello_len = 0;
        }
#else
        if(base_ctx->send_callback != NULL) {
            (void)noxtls_tls_send_alert(base_ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_PROTOCOL_VERSION);
        }
        if(client_hello_data) noxtls_free(client_hello_data);
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else if(detected_version == TLS_VERSION_1_1) {
#if NOXTLS_FEATURE_TLS11
        /* TLS 1.1 */
        if(tls11_ctx == NULL) {
            /*
             * If caller didn't provide a dedicated TLS 1.1 context, spin up
             * a temporary one and mirror TLS 1.2 server configuration into it.
             */
            tls11_context_t tls11_tmp;
            memset(&tls11_tmp, 0, sizeof(tls11_tmp));
            rc = noxtls_tls11_context_init(&tls11_tmp, TLS_ROLE_SERVER);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                if(client_hello_data) noxtls_free(client_hello_data);
                return rc;
            }
            tls11_tmp.base.base.pending_client_hello = client_hello_data;
            tls11_tmp.base.base.pending_client_hello_len = client_hello_len;
            tls11_tmp.base.base.send_callback = base_ctx->send_callback;
            tls11_tmp.base.base.recv_callback = base_ctx->recv_callback;
            tls11_tmp.base.base.user_data = base_ctx->user_data;
            tls11_tmp.base.base.io_mode = base_ctx->io_mode;

            /* Mirror server identity and suite policy from TLS 1.2 context. */
            tls11_tmp.server_cert = tls12_ctx->server_cert;
            tls11_tmp.server_cert_len = tls12_ctx->server_cert_len;
            tls11_tmp.server_cert_chain = tls12_ctx->server_cert_chain;
            tls11_tmp.server_cert_chain_len = tls12_ctx->server_cert_chain_len;
            tls11_tmp.server_cert_chain_count = tls12_ctx->server_cert_chain_count;
            tls11_tmp.server_private_rsa = tls12_ctx->server_private_rsa;
            tls11_tmp.server_cipher_suites = tls12_ctx->server_cipher_suites;
            tls11_tmp.server_cipher_suites_count = tls12_ctx->server_cipher_suites_count;

            rc = noxtls_tls11_accept(&tls11_tmp);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                *negotiated_version = TLS_VERSION_1_1;
            }

            if(tls11_tmp.base.base.pending_client_hello) {
                noxtls_free(tls11_tmp.base.base.pending_client_hello);
                tls11_tmp.base.base.pending_client_hello = NULL;
                tls11_tmp.base.base.pending_client_hello_len = 0;
            }
            noxtls_tls11_context_free(&tls11_tmp);
            return rc;
        }
        tls11_context_t *tls11 = (tls11_context_t*)tls11_ctx;
        tls11->base.base.pending_client_hello = client_hello_data;
        tls11->base.base.pending_client_hello_len = client_hello_len;
        tls11->base.base.send_callback = base_ctx->send_callback;
        tls11->base.base.recv_callback = base_ctx->recv_callback;
        tls11->base.base.user_data = base_ctx->user_data;
        tls11->base.base.io_mode = base_ctx->io_mode;
        rc = noxtls_tls11_accept(tls11);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            *negotiated_version = TLS_VERSION_1_1;
        }
        if(tls11->base.base.pending_client_hello) {
            noxtls_free(tls11->base.base.pending_client_hello);
            tls11->base.base.pending_client_hello = NULL;
            tls11->base.base.pending_client_hello_len = 0;
        }
#else
        if(base_ctx->send_callback != NULL) {
            (void)noxtls_tls_send_alert(base_ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_PROTOCOL_VERSION);
        }
        if(client_hello_data) noxtls_free(client_hello_data);
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else if(detected_version == TLS_VERSION_1_3 && tls13_ctx != NULL) {
        /* Store in TLS 1.3 context */
        tls13_ctx->base.base.pending_client_hello = client_hello_data;
        tls13_ctx->base.base.pending_client_hello_len = client_hello_len;
        
        /* Copy I/O callbacks from base context */
        tls13_ctx->base.base.send_callback = base_ctx->send_callback;
        tls13_ctx->base.base.recv_callback = base_ctx->recv_callback;
        tls13_ctx->base.base.user_data = base_ctx->user_data;
        tls13_ctx->base.base.io_mode = base_ctx->io_mode;
        
        /* Call TLS 1.3 accept */
        rc = noxtls_tls13_accept(tls13_ctx);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            *negotiated_version = TLS_VERSION_1_3;
        }
        
        /* Clean up stored Client Hello */
        if(tls13_ctx->base.base.pending_client_hello) {
            noxtls_free(tls13_ctx->base.base.pending_client_hello);
            tls13_ctx->base.base.pending_client_hello = NULL;
            tls13_ctx->base.base.pending_client_hello_len = 0;
        }
    } else if(detected_version == TLS_VERSION_1_2 ||
              (detected_version == TLS_VERSION_1_3 && tls13_ctx == NULL)) {
        if(detected_version == TLS_VERSION_1_3 && tls13_ctx == NULL) {
            if(!noxtls_tls_client_hello_supported_versions_has(client_hello_data,
                                                              client_hello_len,
                                                              TLS_VERSION_1_2)) {
                if(base_ctx->send_callback != NULL) {
                    (void)noxtls_tls_send_alert(base_ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_HANDSHAKE_FAILURE);
                }
                if(client_hello_data) {
                    noxtls_free(client_hello_data);
                }
                return NOXTLS_RETURN_NOT_SUPPORTED;
            }
        }
        /* Store in TLS 1.2 context */
        tls12_ctx->base.base.pending_client_hello = client_hello_data;
        tls12_ctx->base.base.pending_client_hello_len = client_hello_len;
        
        /* Copy I/O callbacks from base context */
        tls12_ctx->base.base.send_callback = base_ctx->send_callback;
        tls12_ctx->base.base.recv_callback = base_ctx->recv_callback;
        tls12_ctx->base.base.user_data = base_ctx->user_data;
        tls12_ctx->base.base.io_mode = base_ctx->io_mode;
        
        /* Call TLS 1.2 accept */
        rc = noxtls_tls12_accept(tls12_ctx);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            *negotiated_version = TLS_VERSION_1_2;
        }
        
        /* Clean up stored Client Hello */
        if(tls12_ctx->base.base.pending_client_hello) {
            noxtls_free(tls12_ctx->base.base.pending_client_hello);
            tls12_ctx->base.base.pending_client_hello = NULL;
            tls12_ctx->base.base.pending_client_hello_len = 0;
        }
    } else {
        if(base_ctx->send_callback != NULL) {
            (void)noxtls_tls_send_alert(base_ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_PROTOCOL_VERSION);
        }
        if(client_hello_data) {
            noxtls_free(client_hello_data);
        }
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    
    return rc;
}

