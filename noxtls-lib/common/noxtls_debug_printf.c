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
* File:    noxtls_debug_printf.c
* Summary: NoxTLS debug printf abstraction layer implementation
* Currently wraps standard printf, but can be customized per platform
*
*****************************************************************************/

/** @addtogroup noxtls_common */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "noxtls_debug_printf.h"

static unsigned char g_noxtls_debug_level = 1U;
static FILE *g_noxtls_debug_log_fp = NULL;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Print formatted debug output (similar to printf)
 * 
 * Currently wraps the standard printf function. This can be customized
 * for different platforms:
 * - Embedded systems: redirect to UART, SPI, or other I/O
 * - Different logging: redirect to log file, syslog, etc.
 * - Disabled: return immediately for production builds
 */
int noxtls_debug_printf(const char *format, ...)
{
    int result;
    va_list args;
    
    va_start(args, format);
    result = noxtls_debug_vprintf(format, args);
    va_end(args);
    
    return result;
}

/**
 * @brief Print formatted debug output with va_list (similar to vprintf)
 * 
 * This is the core implementation that can be customized per platform.
 * When NDEBUG is defined (Release/production builds), no output is produced
 * to avoid I/O in crypto hot paths (bignum mod/exp, ECC, ECDSA).
 */
int noxtls_debug_vprintf(const char *format, va_list args)
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
    if(g_noxtls_debug_level == 1U && strstr(format, "[TLS13_DEBUG]") != NULL) {
        return 0;
    }
    {
        int stdout_result;
        va_list args_copy;
        va_copy(args_copy, args);
        stdout_result = vprintf(format, args);
        if(g_noxtls_debug_log_fp != NULL) {
            (void)vfprintf(g_noxtls_debug_log_fp, format, args_copy);
            fflush(g_noxtls_debug_log_fp);
        }
        va_end(args_copy);
        return stdout_result;
    }
#endif
}

/**
 * @brief Set the debug level
 * 
 * @param[in] level The debug level
 */
void noxtls_debug_set_level(unsigned char level)
{
    g_noxtls_debug_level = level;
}

/**
 * @brief Get the debug level
 * 
 * @return The debug level
 */
unsigned char noxtls_debug_get_level(void)
{
    return g_noxtls_debug_level;
}

/**
 * @brief Set the log file
 * 
 * @param[in] path The path to the log file
 * @return The return value
 */
int noxtls_debug_set_log_file(const char *path)
{
    if(g_noxtls_debug_log_fp != NULL) {
        fclose(g_noxtls_debug_log_fp);
        g_noxtls_debug_log_fp = NULL;
    }
    if(path == NULL || path[0] == '\0') {
        return 0;
    }
    g_noxtls_debug_log_fp = fopen(path, "a");
    if(g_noxtls_debug_log_fp == NULL) {
        return -1;
    }
    setvbuf(g_noxtls_debug_log_fp, NULL, _IOLBF, 0);
    return 0;
}

#ifdef __cplusplus
}
#endif


