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
 * by examining the Client Hello message, then routes to the appropriate
 * version-specific accept function.
 * 
 * @param base_ctx Base TLS context with I/O callbacks set (must be server role)
 * @param tls10_ctx TLS 1.0 context (must be initialized with tls10_context_init, can be NULL)
 * @param tls11_ctx TLS 1.1 context (must be initialized with tls11_context_init, can be NULL)
 * @param tls12_ctx TLS 1.2 context (must be initialized with tls12_context_init)
 * @param tls13_ctx TLS 1.3 context (must be initialized with tls13_context_init)
 * @param negotiated_version Output: The negotiated TLS version
 * @return NOXTLS_RETURN_SUCCESS on success, error code on failure
 */
noxtls_return_t tls_accept_auto(tls_context_t *base_ctx,
                                   void *tls10_ctx,
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
    
    if(base_ctx == NULL || tls12_ctx == NULL || tls13_ctx == NULL || negotiated_version == NULL) {
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
        return rc;
    }
    
    /* Store Client Hello in the appropriate context for later use */
    if(detected_version == TLS_VERSION_1_0) {
#if NOXTLS_FEATURE_TLS10
        /* TLS 1.0 */
        if(tls10_ctx == NULL) {
            if(client_hello_data) free(client_hello_data);
            return NOXTLS_RETURN_FAILED;  /* TLS 1.0 context not provided */
        }
        tls10_context_t *tls10 = (tls10_context_t*)tls10_ctx;
        tls10->base.base.pending_client_hello = client_hello_data;
        tls10->base.base.pending_client_hello_len = client_hello_len;
        tls10->base.base.send_callback = base_ctx->send_callback;
        tls10->base.base.recv_callback = base_ctx->recv_callback;
        tls10->base.base.user_data = base_ctx->user_data;
        tls10->base.base.io_mode = base_ctx->io_mode;
        rc = tls10_accept(tls10);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            *negotiated_version = TLS_VERSION_1_0;
        }
        if(tls10->base.base.pending_client_hello) {
            free(tls10->base.base.pending_client_hello);
            tls10->base.base.pending_client_hello = NULL;
            tls10->base.base.pending_client_hello_len = 0;
        }
#else
        if(client_hello_data) free(client_hello_data);
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else if(detected_version == TLS_VERSION_1_1) {
#if NOXTLS_FEATURE_TLS11
        /* TLS 1.1 */
        if(tls11_ctx == NULL) {
            if(client_hello_data) free(client_hello_data);
            return NOXTLS_RETURN_FAILED;  /* TLS 1.1 context not provided */
        }
        tls11_context_t *tls11 = (tls11_context_t*)tls11_ctx;
        tls11->base.base.pending_client_hello = client_hello_data;
        tls11->base.base.pending_client_hello_len = client_hello_len;
        tls11->base.base.send_callback = base_ctx->send_callback;
        tls11->base.base.recv_callback = base_ctx->recv_callback;
        tls11->base.base.user_data = base_ctx->user_data;
        tls11->base.base.io_mode = base_ctx->io_mode;
        rc = tls11_accept(tls11);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            *negotiated_version = TLS_VERSION_1_1;
        }
        if(tls11->base.base.pending_client_hello) {
            free(tls11->base.base.pending_client_hello);
            tls11->base.base.pending_client_hello = NULL;
            tls11->base.base.pending_client_hello_len = 0;
        }
#else
        if(client_hello_data) free(client_hello_data);
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else if(detected_version == TLS_VERSION_1_3) {
        /* Store in TLS 1.3 context */
        tls13_ctx->base.base.pending_client_hello = client_hello_data;
        tls13_ctx->base.base.pending_client_hello_len = client_hello_len;
        
        /* Copy I/O callbacks from base context */
        tls13_ctx->base.base.send_callback = base_ctx->send_callback;
        tls13_ctx->base.base.recv_callback = base_ctx->recv_callback;
        tls13_ctx->base.base.user_data = base_ctx->user_data;
        tls13_ctx->base.base.io_mode = base_ctx->io_mode;
        
        /* Call TLS 1.3 accept */
        rc = tls13_accept(tls13_ctx);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            *negotiated_version = TLS_VERSION_1_3;
        }
        
        /* Clean up stored Client Hello */
        if(tls13_ctx->base.base.pending_client_hello) {
            free(tls13_ctx->base.base.pending_client_hello);
            tls13_ctx->base.base.pending_client_hello = NULL;
            tls13_ctx->base.base.pending_client_hello_len = 0;
        }
    } else {
        /* Store in TLS 1.2 context */
        tls12_ctx->base.base.pending_client_hello = client_hello_data;
        tls12_ctx->base.base.pending_client_hello_len = client_hello_len;
        
        /* Copy I/O callbacks from base context */
        tls12_ctx->base.base.send_callback = base_ctx->send_callback;
        tls12_ctx->base.base.recv_callback = base_ctx->recv_callback;
        tls12_ctx->base.base.user_data = base_ctx->user_data;
        tls12_ctx->base.base.io_mode = base_ctx->io_mode;
        
        /* Call TLS 1.2 accept */
        rc = tls12_accept(tls12_ctx);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            *negotiated_version = TLS_VERSION_1_2;
        }
        
        /* Clean up stored Client Hello */
        if(tls12_ctx->base.base.pending_client_hello) {
            free(tls12_ctx->base.base.pending_client_hello);
            tls12_ctx->base.base.pending_client_hello = NULL;
            tls12_ctx->base.base.pending_client_hello_len = 0;
        }
    }
    
    return rc;
}

