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

#ifndef NOXTLS_DEBUG_PRINTF_H_
#define NOXTLS_DEBUG_PRINTF_H_

#include <stddef.h>
#include <stdint.h>
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
#if defined(NOXTLS_DEBUG_PRINTF_STDIO) && (NOXTLS_DEBUG_PRINTF_STDIO != 0)
int noxtls_debug_printf(const uint8_t *format, ...);
/**
 * @brief Optional va_list debug printer (stdio backend only).
 *
 * Declared only when the stdio backend header support is enabled so library
 * translation units do not pull in <stdarg.h> (MISRA 17.1).
 */
#include <stdarg.h>
int noxtls_debug_vprintf(const uint8_t *format, va_list args);
#elif defined(NOXTLS_DEBUG_PRINTF_IMPLEMENTATION)
int noxtls_debug_printf(const uint8_t *format, ...);
#else
/* Freestanding/MISRA stub builds: discard call-site string literals (Rule 7.4 vs Dir 1.1). */
#define noxtls_debug_printf(...) (0)
#endif

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
int noxtls_debug_set_log_file(const uint8_t *path);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_DEBUG_PRINTF_H_ */

