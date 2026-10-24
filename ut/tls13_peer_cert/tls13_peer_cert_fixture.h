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
* File:    tls13_peer_cert_fixture.h
* Summary: In-memory stream fixture for the TLS 1.3 peer certificate tests
*****************************************************************************/
/** @file tls13_peer_cert_fixture.h
 * @brief Test-only pipes, endpoints and bounds.
 * @ingroup noxtls_tls13_peer_cert
 */
#ifndef NOXTLS_TLS13_PEER_CERT_FIXTURE_H
#define NOXTLS_TLS13_PEER_CERT_FIXTURE_H
#include "tls/noxtls_tls13.h"
#include <stdbool.h>
#include <stdint.h>

/** Bytes buffered in one direction; holds a full server flight with a chain. */
#define PEER_CERT_PIPE_BYTES 16384U
/** Upper bound on alternating connect/accept steps. */
#define PEER_CERT_MAX_STEPS 200U
/** Intermediate certificates the server presents after its leaf. */
#define PEER_CERT_INTERMEDIATES 1U
/** Virtual start time in milliseconds. */
#define PEER_CERT_START_MS 1000U
/** Virtual time advanced per step in milliseconds. */
#define PEER_CERT_STEP_MS 10U

/** @brief One direction of the in-memory stream. */
typedef struct {
    uint8_t bytes[PEER_CERT_PIPE_BYTES];
    uint32_t length;
} peer_cert_pipe_t;

/** @brief One TLS 1.3 endpoint and its pipes. */
typedef struct {
    tls13_context_t tls;
    peer_cert_pipe_t *rx;
    peer_cert_pipe_t *tx;
    bool initialized;
} peer_cert_endpoint_t;
#endif
