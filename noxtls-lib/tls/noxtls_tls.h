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
* File:    noxtls_tls.h
* Summary: Transport Layer Security (TLS) Main Header
*
*
*****************************************************************************/

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
/* The caller must provide tls12_ctx; tls10_ctx and tls11_ctx are optional (can be NULL). */
/* tls13_ctx may be NULL to disable TLS 1.3: clients that offer TLS 1.2 in supported_versions negotiate TLS 1.2. */
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

