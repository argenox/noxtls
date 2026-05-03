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
* File:    noxtls_memory_compat.h
* Summary: Memory Function Compatibility Macros
*
* This header provides macros to replace standard malloc/free/calloc/realloc
* with NOXTLS memory management functions. Include this header after
* including NOXTLS_memory.h to enable the replacements.
*
* Note: Only include this in library code, not in applications that may
*       need to use standard malloc/free for their own purposes.
*
*/

/** @addtogroup noxtls_common */
/** @{ */

#ifndef _NOXTLS_MEMORY_COMPAT_H_
#define _NOXTLS_MEMORY_COMPAT_H_

#include "noxtls_memory.h"

/* Redefine standard memory functions to use NOXTLS allocator */
#undef malloc
#undef free
#undef calloc
#undef realloc

#define malloc(size) noxtls_malloc(size)
#define free(ptr) noxtls_free(ptr)
#define calloc(nmemb, size) noxtls_calloc(nmemb, size)
#define realloc(ptr, size) noxtls_realloc(ptr, size)

#endif /* _NOXTLS_MEMORY_COMPAT_H_ */


