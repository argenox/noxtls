/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* NOTICE:  All information contained herein, source code, binaries and
* derived works is, and remains
* the property of Argenox Technologies and its suppliers,
* if any.  The intellectual and technical concepts contained
* herein are proprietary to Argenox Technologies
* and its suppliers may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Argenox Technologies.
*
* THIS SOFTWARE IS PROVIDED BY ARGENOX "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ARGENOX TECHNOLOGIES LLC BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_debug_printf.h
* Summary: NOXTLS debug printf abstraction layer
* Provides platform-independent printf functionality for debugging
*
*/

/** @addtogroup noxtls_common */
/** @{ */

#ifndef _NOXTLS_DEBUG_PRINTF_H_
#define _NOXTLS_DEBUG_PRINTF_H_

#include <stdarg.h>
#include <stddef.h>

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

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_DEBUG_PRINTF_H_ */


