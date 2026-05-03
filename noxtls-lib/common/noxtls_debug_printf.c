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
* File:    noxtls_debug_printf.c
* Summary: NOXTLS debug printf abstraction layer implementation
* Currently wraps standard printf, but can be customized per platform
*
*/

/** @addtogroup noxtls_common */

#include <stdio.h>
#include <stdarg.h>
#include "noxtls_debug_printf.h"

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
    return vprintf(format, args);
#endif
}

#ifdef __cplusplus
}
#endif


