/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    noxtls_ct.c
* Summary: Constant-time and secret-handling memory helpers
*
*/

/** @addtogroup noxtls_common */

#include <string.h>

#include "noxtls_config.h"
#include "noxtls_ct.h"

/**
 * @brief Constant-time comparison of two buffers (no early exit on first difference).
 * @param[in] a First buffer; if NULL, comparison fails (non-zero return).
 * @param[in] b Second buffer; if NULL, comparison fails (non-zero return).
 * @param[in] len Number of bytes to compare.
 * @return 0 if @p a and @p b compare equal over @p len bytes; otherwise non-zero.
 */
int noxtls_ct_memcmp(const void *a, const void *b, size_t len)
{
    const uint8_t *pa;
    const uint8_t *pb;
    uint8_t diff = 0;
    size_t i;

    if(a == NULL || b == NULL) {
        return 1;
    }

    pa = (const uint8_t *)a;
    pb = (const uint8_t *)b;

    for(i = 0; i < len; i++) {
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    }

    return (int)diff;
}

/**
 * @brief Equality test built on @ref noxtls_ct_memcmp.
 * @param[in] a First buffer.
 * @param[in] b Second buffer.
 * @param[in] len Number of bytes to compare.
 * @return 1 if buffers are equal over @p len bytes, 0 if not equal or if either pointer is NULL.
 */
int noxtls_ct_equal(const void *a, const void *b, size_t len)
{
    return (noxtls_ct_memcmp(a, b, len) == 0);
}

/**
 * @brief Secret comparison; uses constant-time compare when `NOXTLS_CT_COMPARE` is enabled.
 * @param[in] a First buffer.
 * @param[in] b Second buffer.
 * @param[in] len Number of bytes to compare.
 * @return With `NOXTLS_CT_COMPARE`: same as @ref noxtls_ct_memcmp. Otherwise `memcmp` semantics (0 if equal, non-zero with sign per `memcmp`).
 */
int noxtls_secret_memcmp(const void *a, const void *b, size_t len)
{
#if NOXTLS_CT_COMPARE
    return noxtls_ct_memcmp(a, b, len);
#else
    return memcmp(a, b, len);
#endif
}

/**
 * @brief Clears a buffer using a volatile store sequence to reduce risk of the compiler removing the zeroing.
 * @param[in,out] ptr Region to overwrite; no-op if NULL.
 * @param[in]     len Size in bytes; no-op if zero.
 * @return None.
 */
void noxtls_secure_zero(void *ptr, size_t len)
{
    volatile uint8_t *p;

    if(ptr == NULL || len == 0) {
        return;
    }

    p = (volatile uint8_t *)ptr;
    while(len > 0) {
        *p++ = 0;
        len--;
    }
}
