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
* File:    noxtls_memory_compat.h
* Summary: Memory Function Compatibility Macros
*
* This header provides macros to replace standard malloc/free/calloc/realloc
* with NoxTLS memory management functions. Include this header after
* including NOXTLS_memory.h to enable the replacements.
*
* Note: Only include this in library code, not in applications that may
*       need to use standard malloc/free for their own purposes.
*
*****************************************************************************/

/** @addtogroup noxtls_common */
/** @{ */

#ifndef _NOXTLS_MEMORY_COMPAT_H_
#define _NOXTLS_MEMORY_COMPAT_H_

#include "noxtls_memory.h"

/* Redefine standard memory functions to use NoxTLS allocator */
#undef malloc
#undef free
#undef calloc
#undef realloc

#define malloc(size) noxtls_malloc(size)
#define free(ptr) noxtls_free(ptr)
#define calloc(nmemb, size) noxtls_calloc(nmemb, size)
#define realloc(ptr, size) noxtls_realloc(ptr, size)

#endif /* _NOXTLS_MEMORY_COMPAT_H_ */


