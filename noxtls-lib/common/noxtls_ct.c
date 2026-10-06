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
* File:    noxtls_ct.c
* Summary: Constant-time and secret-handling memory helpers
*
*/

/** @addtogroup noxtls_common */

#include <string.h>
#include <stdint.h>

#include "noxtls_config.h"
#include "noxtls_ct.h"

/**
 * @brief Constant-time comparison of two buffers (no early exit on first difference).
 * @param[in] a First buffer; if NULL, comparison fails (non-zero return).
 * @param[in] b Second buffer; if NULL, comparison fails (non-zero return).
 * @param[in] len Number of bytes to compare.
 * @return 0 if @p a and @p b compare equal over @p len bytes; otherwise non-zero.
 */
/* SECURITY: must remain constant-time (no early exit). */
int noxtls_ct_memcmp(const void *a, const void *b, size_t len)
{
    const uint8_t *pa;
    const uint8_t *pb;
    uint8_t diff = 0U;
    size_t i;

    if((a == NULL) || (b == NULL)) {
        return 1;
    }

    pa = (const uint8_t *)a;
    pb = (const uint8_t *)b;

    for(i = 0U; i < len; i += 1U) {
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
    return (noxtls_ct_memcmp(a, b, len) == 0) ? 1 : 0;
}

/**
 * @brief Secret comparison; uses constant-time compare when `NOXTLS_CT_COMPARE` is enabled.
 * @param[in] a First buffer.
 * @param[in] b Second buffer.
 * @param[in] len Number of bytes to compare.
 * @return Same as @ref noxtls_ct_memcmp: 0 if equal over @p len bytes, otherwise non-zero. Always constant-time.
 */
int noxtls_secret_memcmp(const void *a, const void *b, size_t len)
{
    /*
     * SECURITY (NX-07): comparisons of secrets (MACs, AEAD tags, Finished
     * verify_data, PSK binders) must never short-circuit. This is intentionally
     * constant-time regardless of the side-channel performance profile; only
     * non-secret comparisons may use plain memcmp.
     */
    return noxtls_ct_memcmp(a, b, len);
}

/**
 * @brief Clears a buffer using a volatile store sequence to reduce risk of the compiler removing the zeroing.
 * @param[in,out] ptr Region to overwrite; no-op if NULL.
 * @param[in]     len Size in bytes; no-op if zero.
 * @return None.
 */
/* SECURITY: volatile walk must not be optimized away; pointer increment is intentional. */
void noxtls_secure_zero(void *ptr, size_t len)
{
    volatile uint8_t *p;
    size_t remaining = len;

    if((ptr == NULL) || (remaining == 0U)) {
        return;
    }

    p = (volatile uint8_t *)ptr;
    while(remaining > 0U) {
        *p = 0u;
        p = &p[1];
        remaining -= 1U;
    }
}

void noxtls_copy_u8(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t n)
{
    size_t i = 0U;
    size_t lim = n;

    if((dst == NULL) || (src == NULL) || (dst_cap == 0U) || (n == 0U)) {
        return;
    }
    if(lim > dst_cap) {
        lim = dst_cap;
    }
    for(i = 0U; i < lim; i += 1U) {
        dst[i] = src[i];
    }
}

void noxtls_fill_u8(uint8_t *dst, size_t dst_cap, uint8_t fill_byte, size_t n)
{
    size_t i = 0U;
    size_t lim = n;

    if((dst == NULL) || (dst_cap == 0U) || (n == 0U)) {
        return;
    }
    if(lim > dst_cap) {
        lim = dst_cap;
    }
    for(i = 0U; i < lim; i += 1U) {
        dst[i] = fill_byte;
    }
}

void noxtls_move_u8(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t n)
{
    size_t i = 0U;
    size_t lim = n;

    if((dst == NULL) || (src == NULL) || (dst_cap == 0U) || (n == 0U) ||
       ((uintptr_t)dst == (uintptr_t)src)) {
        return;
    }
    if(lim > dst_cap) {
        lim = dst_cap;
    }
    if((uintptr_t)dst < (uintptr_t)src) {
        for(i = 0U; i < lim; i += 1U) {
            dst[i] = src[i];
        }
    } else {
        i = lim;
        while(i > 0U) {
            i -= 1U;
            dst[i] = src[i];
        }
    }
}

size_t noxtls_u8_strlen(const uint8_t *s)
{
    size_t n = 0U;

    if(s == NULL) {
        return 0U;
    }
    while(s[n] != 0U) {
        n += 1U;
    }
    return n;
}

int noxtls_u8_strcmp(const uint8_t *a, const uint8_t *b)
{
    size_t i = 0U;

    if(a == b) {
        return 0;
    }
    if(a == NULL) {
        return -1;
    }
    if(b == NULL) {
        return 1;
    }
    while((a[i] != 0U) && (a[i] == b[i])) {
        i += 1U;
    }
    return (int)a[i] - (int)b[i];
}

int noxtls_u8_strncmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    size_t i = 0U;

    if(n == 0U) {
        return 0;
    }
    if(a == b) {
        return 0;
    }
    if(a == NULL) {
        return -1;
    }
    if(b == NULL) {
        return 1;
    }
    while((i < n) && (a[i] != 0U) && (a[i] == b[i])) {
        i += 1U;
    }
    if(i == n) {
        return 0;
    }
    return (int)a[i] - (int)b[i];
}


#include "noxtls_time.h"
#include "noxtls_config.h"

#if NOXTLS_HAVE_TIME
#include <time.h>
#endif

#if defined(ESP_PLATFORM)
#include "esp_timer.h"
#endif

noxtls_unix_time_t noxtls_time_unix_seconds(void)
{
#if NOXTLS_HAVE_TIME
    time_t now = time(NULL);
    if(now == (time_t)-1) {
        return (noxtls_unix_time_t)-1;
    }
    return (noxtls_unix_time_t)now;
#else
    return (noxtls_unix_time_t)-1;
#endif
}

uint64_t noxtls_time_mono_us(void)
{
#if defined(ESP_PLATFORM)
    return (uint64_t)esp_timer_get_time();
#elif NOXTLS_HAVE_TIME
    {
        clock_t now = clock();
        if(now <= (clock_t)0) {
            return 0U;
        }
        return ((uint64_t)now * 1000000U) / (uint64_t)CLOCKS_PER_SEC;
    }
#else
    return 0U;
#endif
}
