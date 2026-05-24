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
* File:    noxtls_debug_printf.h
* Summary: NoxTLS debug printf abstraction layer
* Provides platform-independent printf functionality for debugging
*
*****************************************************************************/

/** @addtogroup noxtls_common */
/** @{ */

#ifndef _NOXTLS_DEBUG_PRINTF_H_
#define _NOXTLS_DEBUG_PRINTF_H_

#include <stdarg.h>
#include <stddef.h>
#include "noxtls_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Print formatted debug output (similar to printf)
 * 
 * This function provides a platform-independent way to print formatted debug output.
 * Currently, it wraps the standard printf function, but can be customized
 * for different platforms (e.g., embedded systems, different logging mechanisms).
 * 
 * @param[in] format Format string (same as printf)
 * @param[in] ... Variable arguments (same as printf)
 * 
 * @return Number of characters printed, or negative value on error
 */
int noxtls_debug_printf(const char *format, ...);

/**
 * @brief Print formatted debug output with va_list (similar to vprintf)
 * 
 * This function is the va_list version of noxtls_debug_printf, useful for
 * creating wrapper functions.
 * 
 * @param[in] format Format string (same as printf)
 * @param[in] args Variable argument list
 * 
 * @return Number of characters printed, or negative value on error
 */
int noxtls_debug_vprintf(const char *format, va_list args);

/**
 * @brief Set runtime debug verbosity level for noxtls_debug_printf.
 *
 * Levels:
 *   0 = disabled
 *   1 = standard debug (suppresses very chatty TLS13 traces)
 *   2 = full debug output
 *
 * @param[in] level Debug level.
 */
void noxtls_debug_set_level(unsigned char level);

/**
 * @brief Get runtime debug verbosity level.
 *
 * @return Current debug level.
 */
unsigned char noxtls_debug_get_level(void);

/**
 * @brief Configure optional debug log output file.
 *
 * When configured, debug output is still printed to stdout and also appended
 * to the specified file. Pass NULL or an empty string to disable file logging.
 *
 * @param[in] path Log file path to open in append mode, or NULL/empty to disable.
 * @return 0 on success, -1 on failure (e.g., file open error).
 */
int noxtls_debug_set_log_file(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_DEBUG_PRINTF_H_ */


