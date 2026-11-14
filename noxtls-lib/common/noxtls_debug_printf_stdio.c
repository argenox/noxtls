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
* File:    noxtls_debug_printf_stdio.c
* Summary: Optional stdio-backed debug printf (host/debug builds)
* Currently wraps standard printf, but can be customized per platform
*
*****************************************************************************/

/** @addtogroup noxtls_common */

/* Rule 17.1 / 21.6: debug facade intentionally uses stdarg + stdio. */
#define NOXTLS_DEBUG_PRINTF_STDIO 1
#include <stdarg.h>
#include <string.h>
#include "noxtls_debug_printf.h"

#ifndef NDEBUG
#include <stdio.h>
#endif

/* Fail quiet by default: TLS diagnostics can include handshake material. */
static unsigned char g_noxtls_debug_level = 0U;
#ifndef NDEBUG
static FILE *g_noxtls_debug_log_fp = NULL;
/* Set while a suppressed [TLS13_DEBUG] line is still being printed piecewise. */
static unsigned char g_noxtls_debug_in_suppressed_line = 0U;
#endif

#ifdef __cplusplus
extern "C" {
#endif

int noxtls_debug_printf(const uint8_t *format, ...)
{
    int result;
    va_list args;

    va_start(args, format);
    result = noxtls_debug_vprintf(format, args);
    va_end(args);

    return result;
}

#ifndef NDEBUG
/**
 * @brief Report whether @p format only prints bytes as hex ("%02X", "%02x", with optional spaces).
 *
 * Library code dumps buffers one byte per call with such formats, and the
 * bytes can be key material. These calls carry no marker of their own.
 *
 * @param[in] format NUL-terminated format string.
 * @return 1 for a bare hex-byte format, 0 otherwise.
 */
static int noxtls_debug_is_hex_byte_format(const char *format)
{
    const char *p = format;
    int conversions = 0;

    while(*p != '\0') {
        if(*p == ' ') {
            p++;
        } else if((p[0] == '%') && (p[1] == '0') && (p[2] == '2') && ((p[3] == 'X') || (p[3] == 'x'))) {
            conversions += 1;
            p = &p[4];
        } else {
            return 0;
        }
    }
    return (conversions > 0) ? 1 : 0;
}

/**
 * @brief Decide whether level 1 must drop this call.
 *
 * Level 1 drops [TLS13_DEBUG] lines, including the per-byte calls and the
 * closing newline that continue such a line, and every bare hex-byte dump,
 * because those dumps carry secrets (shared secrets, traffic keys, private
 * scalars) and cannot be told apart from harmless ones by their format.
 *
 * @param[in] format NUL-terminated format string.
 * @return 1 to drop the call, 0 to print it.
 */
static int noxtls_debug_level1_suppressed(const char *format)
{
    size_t len = strlen(format);
    int ends_line = ((len > 0U) && (format[len - 1U] == '\n')) ? 1 : 0;
    int suppress = 0;

    if(strstr(format, "[TLS13_DEBUG]") != NULL) {
        suppress = 1;
        g_noxtls_debug_in_suppressed_line = (ends_line != 0) ? 0U : 1U;
    } else if(g_noxtls_debug_in_suppressed_line != 0U) {
        suppress = 1;
        if(ends_line != 0) {
            g_noxtls_debug_in_suppressed_line = 0U;
        }
    } else if(noxtls_debug_is_hex_byte_format(format) != 0) {
        suppress = 1;
    } else {
        suppress = 0;
    }
    return suppress;
}
#endif

int noxtls_debug_vprintf(const uint8_t *format, va_list args)
{
#ifdef NDEBUG
    (void)format;
    (void)args;
    return 0;
#else
    if(format == NULL) {
        return 0;
    }
    if(g_noxtls_debug_level == 0U) {
        return 0;
    }
    if((g_noxtls_debug_level == 1U) && (noxtls_debug_level1_suppressed((const char *)(const void *)format) != 0)) {
        return 0;
    }
    {
        int stdout_result;
        va_list args_copy;
        va_copy(args_copy, args);
        stdout_result = vprintf((const char *)(const void *)format, args);
        if(g_noxtls_debug_log_fp != NULL) {
            (void)vfprintf(g_noxtls_debug_log_fp, (const char *)(const void *)format, args_copy);
        }
        va_end(args_copy);
        return stdout_result;
    }
#endif
}

void noxtls_debug_set_level(unsigned char level)
{
    g_noxtls_debug_level = level;
#ifndef NDEBUG
    g_noxtls_debug_in_suppressed_line = 0U;
#endif
}

unsigned char noxtls_debug_get_level(void)
{
    return g_noxtls_debug_level;
}

int noxtls_debug_set_log_file(const uint8_t *path)
{
#ifdef NDEBUG
    (void)path;
    return 0;
#else
    if(g_noxtls_debug_log_fp != NULL) {
        (void)fclose(g_noxtls_debug_log_fp);
        g_noxtls_debug_log_fp = NULL;
    }
    if((path == NULL) || (path[0] == 0U)) {
        return 0;
    }
    g_noxtls_debug_log_fp = fopen((const char *)(const void *)path, "a");
    if(g_noxtls_debug_log_fp == NULL) {
        return -1;
    }
    (void)setvbuf(g_noxtls_debug_log_fp, NULL, _IOLBF, 0);
    return 0;
#endif
}

#ifdef __cplusplus
}
#endif
