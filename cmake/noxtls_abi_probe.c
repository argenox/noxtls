/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_abi_probe.c
* Summary: Configure-time probe of the TLS context sizes (cmake/noxtls_abi.cmake)
*****************************************************************************/

/**
 * @file noxtls_abi_probe.c
 * @brief Embed the sizes of the public TLS contexts as text in an object.
 *
 * cmake/noxtls_abi.cmake compiles this file with the library's flags, without
 * running it, and reads "NOXTLS_ABI_SIZES[...]" from the object, as CMake's
 * CheckTypeSize does, so it works for cross compilers.
 */

#define NOXTLS_ABI_NO_REFERENCE 1
#include "noxtls_tls_common.h"
#include "noxtls_dtls_common.h"
#include "noxtls_tls13.h"
#include "noxtls_connection_memory.h"
#if NOXTLS_FEATURE_TLS12
#include "noxtls_tls12.h"
#endif

/** One decimal digit of @p v at power @p p. */
#define NOXTLS_ABI_DIGIT(v, p) ((char)('0' + (int)(((v) / (p)) % 10U)))
/** Seven decimal digits of a size, then a comma. */
#define NOXTLS_ABI_SIZE(v) \
    NOXTLS_ABI_DIGIT((v), 1000000U), NOXTLS_ABI_DIGIT((v), 100000U), NOXTLS_ABI_DIGIT((v), 10000U), \
    NOXTLS_ABI_DIGIT((v), 1000U), NOXTLS_ABI_DIGIT((v), 100U), NOXTLS_ABI_DIGIT((v), 10U), \
    NOXTLS_ABI_DIGIT((v), 1U), ','

#if NOXTLS_CONN_MEMORY
#define NOXTLS_ABI_CONN_SIZE sizeof(noxtls_connection_memory_t)
#else
#define NOXTLS_ABI_CONN_SIZE 0U
#endif

#if NOXTLS_FEATURE_TLS12
#define NOXTLS_ABI_TLS12_SIZE sizeof(tls12_context_t)
#else
#define NOXTLS_ABI_TLS12_SIZE 0U
#endif

/** The sizes as text; extern so no compiler drops it. */
extern const char noxtls_abi_probe_sizes[];
const char noxtls_abi_probe_sizes[] = {
    'N', 'O', 'X', 'T', 'L', 'S', '_', 'A', 'B', 'I', '_', 'S', 'I', 'Z', 'E', 'S', '[',
    NOXTLS_ABI_SIZE(sizeof(tls_context_t)),
    NOXTLS_ABI_SIZE(sizeof(dtls_context_t)),
    NOXTLS_ABI_SIZE(sizeof(tls13_context_t)),
    NOXTLS_ABI_SIZE(NOXTLS_ABI_TLS12_SIZE),
    NOXTLS_ABI_SIZE(NOXTLS_ABI_CONN_SIZE),
    NOXTLS_ABI_SIZE(sizeof(void *)),
    ']', '\0'
};
