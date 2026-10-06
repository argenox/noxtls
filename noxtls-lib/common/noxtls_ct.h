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
* File:    noxtls_ct.h
* Summary: Constant-time and secret-handling memory helpers
*
*****************************************************************************/

#ifndef NOXTLS_CT_H_
#define NOXTLS_CT_H_

#include <stddef.h>
#include <stdint.h>
#include "noxtls_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Constant-time compare for secrets.
 * Returns 0 when equal, non-zero when different.
 */
int noxtls_ct_memcmp(const void *a, const void *b, size_t len);

/* Convenience wrapper for equality checks. */
int noxtls_ct_equal(const void *a, const void *b, size_t len);

/*
 * Profile-aware secret comparison:
 * - performance profile: may use regular memcmp
 * - balanced/constant_time_strict: uses constant-time compare
 */
int noxtls_secret_memcmp(const void *a, const void *b, size_t len);

/*
 * Zero memory in a way that avoids compiler elision.
 */
void noxtls_secure_zero(void *ptr, size_t len);

/*
 * Non-overlapping byte copy (string.h-free) for Mandatory Rule 21.18 remaps.
 * Copies min(n, dst_cap) bytes.
 */
void noxtls_copy_u8(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t n);

/*
 * Bounded byte fill (string.h-free) for Mandatory Rule 21.18 remaps.
 * Writes value to min(n, dst_cap) bytes of dst.
 */
void noxtls_fill_u8(uint8_t *dst, size_t dst_cap, uint8_t fill_byte, size_t n);

/*
 * Overlap-safe byte move (memmove semantics, string.h-free).
 * Moves min(n, dst_cap) bytes.
 */
void noxtls_move_u8(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t n);

/*
 * NUL-terminated uint8_t text helpers (avoid plain char / libc string APIs in MISRA TUs).
 */
size_t noxtls_u8_strlen(const uint8_t *s);
int noxtls_u8_strcmp(const uint8_t *a, const uint8_t *b);
int noxtls_u8_strncmp(const uint8_t *a, const uint8_t *b, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_CT_H_ */
