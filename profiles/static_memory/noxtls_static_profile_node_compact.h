/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from Argenox Technologies LLC.
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
* File:    noxtls_static_profile_node_compact.h
* Summary: Static memory profile: the node profile without a server workspace slot
*****************************************************************************/
/**
 * @file noxtls_static_profile_node_compact.h
 * @brief noxtls_static_profile_node.h with NOXTLS_STATIC_HS_WORKSPACE_IN_ARENA: the DTLS
 *        1.3 server has no 4 KB handshake workspace slot; its message builders take their
 *        buffers from the handshake arena while they build a message. The server's
 *        handshake part is 4,096 bytes smaller and the arena keeps the node profile's size.
 *
 * Use: -DNOXTLS_STATIC_MEMORY_PROFILE="profiles/static_memory/noxtls_static_profile_node_compact.h".
 * The server block is NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_SERVER, DTLS13_PSK) bytes
 * (or _SPLIT: NOXTLS_CONNECTION_MEMORY_HANDSHAKE_SIZE(TLS_ROLE_SERVER, DTLS13_PSK)). Client
 * contexts of the same build keep their workspace slot.
 *
 * Measured (x86-64 host, node features, ut/static_memory, ut/multi_context, the DTLS 1.3
 * recovery cases and ut/dtls13_single_association run under this sizing): the server's
 * handshake arena peaks at 8,848 bytes with X25519 and 9,016 bytes with a HelloRetryRequest
 * for P-256 (8,048 and 8,080 with the workspace slot). The arena below is that worst case
 * plus 25%, which equals the node profile's derived arena. A build with FFDHE or ML-KEM
 * keeps the default ServerHello builder buffers (2 x 2,048 bytes instead of 512 + 256) and
 * adds the difference with the reserve. The arena is a literal: the ABI fingerprint
 * evaluates it in #if. noxtls_connection_memory.c checks the builders against
 * NOXTLS_STATIC_COMPACT_BUILDERS_BUDGET.
 */
#ifndef NOXTLS_STATIC_PROFILE_NODE_COMPACT_H_
#define NOXTLS_STATIC_PROFILE_NODE_COMPACT_H_

#ifndef NOXTLS_STATIC_HS_WORKSPACE_IN_ARENA
#define NOXTLS_STATIC_HS_WORKSPACE_IN_ARENA 1
#endif
#ifndef NOXTLS_STATIC_HS_ARENA_DTLS_PSK
#if (defined(NOXTLS_FEATURE_DH) && (NOXTLS_FEATURE_DH != 0)) || \
    (defined(NOXTLS_FEATURE_ML_KEM) && (NOXTLS_FEATURE_ML_KEM != 0))
/* Builder region costs 2 x (2,048 + 16) = 4,128 bytes. */
#define NOXTLS_STATIC_COMPACT_BUILDERS_BUDGET 4128U
/* 11,272 + (4,128 - 800) + 25% = 15,432. */
#define NOXTLS_STATIC_HS_ARENA_DTLS_PSK 15432U
#else
/* Builder region costs (512 + 16) + (256 + 16) = 800 bytes. */
#define NOXTLS_STATIC_COMPACT_BUILDERS_BUDGET 800U
/* 9,016 measured + 25% = 11,270, rounded up to 8 bytes. */
#define NOXTLS_STATIC_HS_ARENA_DTLS_PSK 11272U
#endif
#endif

#include "profiles/static_memory/noxtls_static_profile_node.h"

#endif /* NOXTLS_STATIC_PROFILE_NODE_COMPACT_H_ */
