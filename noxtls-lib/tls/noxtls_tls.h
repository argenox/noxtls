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
* File:    noxtls_tls.h
* Summary: Transport Layer Security (TLS) Main Header
*
*/

#ifndef _NOXTLS_TLS_H_
#define _NOXTLS_TLS_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_tls_common.h"
#include "noxtls_tls10.h"
#include "noxtls_tls11.h"
#include "noxtls_tls12.h"
#include "noxtls_tls13.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Unified TLS Accept Function with Automatic Version Negotiation */
/* This function automatically detects TLS version (1.0, 1.1, 1.2, or 1.3) and routes to the appropriate handler */
/* The caller must provide tls12_ctx and tls13_ctx; tls10_ctx and tls11_ctx are optional (can be NULL) */
noxtls_return_t tls_accept_auto(tls_context_t *base_ctx,
                                   void *tls10_ctx,
                                   void *tls11_ctx,
                                   tls12_context_t *tls12_ctx, 
                                   tls13_context_t *tls13_ctx,
                                   uint16_t *negotiated_version);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_TLS_H_ */

