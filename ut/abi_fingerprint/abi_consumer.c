/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    abi_consumer.c
* Summary: A consumer translation unit for the ABI fingerprint link tests
*****************************************************************************/

/**
 * @file abi_consumer.c
 * @brief Include the TLS 1.3 / DTLS 1.3 context headers and nothing else.
 *
 * Its only external reference is the ABI fingerprint symbol noxtls_abi.h
 * emits, so linking it against noxtls_common succeeds exactly when it was
 * compiled with the library's layout.
 */

#include <stdio.h>

#include "noxtls_tls13.h"

/** Stringify an expanded macro. */
#define ABI_STR2(x) #x
#define ABI_STR(x) ABI_STR2(x)

/**
 * @brief Report the fingerprint this translation unit requires.
 * @return 0.
 */
int main(void)
{
    (void)printf("requires %s\n", ABI_STR(NOXTLS_ABI_SYMBOL));
    return 0;
}
