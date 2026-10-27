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
* File:    noxtls_static_footprint.c
* Summary: Static memory footprint table of one configuration
*****************************************************************************/
/**
 * @file noxtls_static_footprint.c
 * @brief Build-time sizes of NOXTLS_CONFIG_STATIC_MEMORY for one configuration.
 *
 * The table is a constant array of the sizing macros. static_memory_footprint.py
 * compiles this file with any compiler (host or cross, for example
 * arm-none-eabi-gcc -mcpu=cortex-m4) and the target's NoxTLS configuration, then
 * reads the array from the object file, so the numbers are the target's own
 * sizeof() values. Defining NOXTLS_FOOTPRINT_MAIN builds a host program that
 * prints the same table.
 */
#include <stdint.h>
#include "tls/noxtls_connection_memory.h"

#if !NOXTLS_CONN_MEMORY
#error "Build with NOXTLS_CONFIG_STATIC_MEMORY=1 and TLS 1.3"
#endif

#define FP_PROFILE(p) \
    (uint32_t)NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, p), \
    (uint32_t)NOXTLS_CONNECTION_MEMORY_STEADY_SIZE(TLS_ROLE_CLIENT, p), \
    (uint32_t)NOXTLS_CONNECTION_MEMORY_HANDSHAKE_SIZE(TLS_ROLE_CLIENT, p)

/** Footprint table; the order is the one static_memory_footprint.py names. */
#if defined(__GNUC__)
__attribute__((used, section(".rodata.noxtls_footprint")))
#endif
const uint32_t noxtls_static_footprint[] = {
    0x4E584650UL, /* "NXFP" */
    FP_PROFILE(TLS13_PSK),
    FP_PROFILE(DTLS13_PSK),
    FP_PROFILE(TLS13_CERT),
    FP_PROFILE(DTLS13_CERT),
    (uint32_t)sizeof(tls13_context_t),
    (uint32_t)sizeof(tls13_hs_state_t),
    (uint32_t)NOXTLS_CONN_HEADER_BYTES,
    (uint32_t)NOXTLS_CONN_TX_BYTES,
    (uint32_t)NOXTLS_CONN_A(TLS13_RECORD_WORKSPACE_SIZE),
    (uint32_t)NOXTLS_CONN_A(TLS_HANDSHAKE_WORKSPACE_SIZE),
    (uint32_t)NOXTLS_CONN_A(NOXTLS_STATIC_DTLS_FLIGHT_SIZE),
    (uint32_t)NOXTLS_CONN_A(NOXTLS_STATIC_HS_ARENA_PSK),
    (uint32_t)NOXTLS_CONN_A(NOXTLS_STATIC_HS_ARENA_DTLS_PSK),
    (uint32_t)NOXTLS_CONN_A(NOXTLS_STATIC_HS_ARENA_CERT),
    (uint32_t)NOXTLS_CONN_A(NOXTLS_STATIC_STEADY_ARENA),
    (uint32_t)NOXTLS_CONN_A(NOXTLS_STATIC_STEADY_ARENA_DTLS),
    (uint32_t)NOXTLS_STATIC_GLOBAL_POOL_SIZE,
    (uint32_t)NOXTLS_STATIC_TRUST_STORE_BYTES,
    (uint32_t)NOXTLS_TLS_MAX_RECORD_SIZE,
    (uint32_t)sizeof(void *),
    /* DTLS 1.3 PSK server (without a workspace slot with NOXTLS_STATIC_HS_WORKSPACE_IN_ARENA). */
    (uint32_t)NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_SERVER, DTLS13_PSK),
    (uint32_t)NOXTLS_CONNECTION_MEMORY_STEADY_SIZE(TLS_ROLE_SERVER, DTLS13_PSK),
    (uint32_t)NOXTLS_CONNECTION_MEMORY_HANDSHAKE_SIZE(TLS_ROLE_SERVER, DTLS13_PSK),
    /* DTLS 1.3 PSK with a 512-byte record budget (noxtls_dtls13_context_init_static_record()). */
    (uint32_t)NOXTLS_CONNECTION_MEMORY_SIZE_RECORD(TLS_ROLE_CLIENT, DTLS13_PSK, 512U),
    (uint32_t)NOXTLS_CONNECTION_MEMORY_STEADY_SIZE_RECORD(TLS_ROLE_CLIENT, DTLS13_PSK, 512U),
    (uint32_t)NOXTLS_CONNECTION_MEMORY_HANDSHAKE_SIZE_RECORD(TLS_ROLE_CLIENT, DTLS13_PSK, 512U),
    (uint32_t)NOXTLS_CONNECTION_MEMORY_SIZE_RECORD(TLS_ROLE_SERVER, DTLS13_PSK, 512U),
    (uint32_t)NOXTLS_CONNECTION_MEMORY_STEADY_SIZE_RECORD(TLS_ROLE_SERVER, DTLS13_PSK, 512U),
    (uint32_t)NOXTLS_CONNECTION_MEMORY_HANDSHAKE_SIZE_RECORD(TLS_ROLE_SERVER, DTLS13_PSK, 512U),
};

#if defined(NOXTLS_FOOTPRINT_MAIN)
#include <stdio.h>

int main(void)
{
    static const char *const names[] = {
        "magic",
        "TLS13_PSK total", "TLS13_PSK steady", "TLS13_PSK released",
        "DTLS13_PSK total", "DTLS13_PSK steady", "DTLS13_PSK released",
        "TLS13_CERT total", "TLS13_CERT steady", "TLS13_CERT released",
        "DTLS13_CERT total", "DTLS13_CERT steady", "DTLS13_CERT released",
        "sizeof(tls13_context_t)", "sizeof(tls13_hs_state_t)", "connection header",
        "record TX buffer", "DTLS record workspace", "handshake workspace", "DTLS flight",
        "handshake arena TLS PSK", "handshake arena DTLS PSK", "handshake arena TLS cert",
        "steady arena TLS", "steady arena DTLS", "global arena", "trust store",
        "record size", "pointer size",
        "DTLS13_PSK server total", "DTLS13_PSK server steady", "DTLS13_PSK server released",
        "DTLS13_PSK r512 total", "DTLS13_PSK r512 steady", "DTLS13_PSK r512 released",
        "DTLS13_PSK r512 server total", "DTLS13_PSK r512 server steady", "DTLS13_PSK r512 server released",
    };
    size_t i;
    for(i = 1U; i < (sizeof(noxtls_static_footprint) / sizeof(noxtls_static_footprint[0])); i++) {
        printf("%-28s %8lu\n", names[i], (unsigned long)noxtls_static_footprint[i]);
    }
    return 0;
}
#endif
