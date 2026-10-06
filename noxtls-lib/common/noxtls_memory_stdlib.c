/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_memory_stdlib.c
* Summary: Host allocator definitions live in noxtls_memory.c (!STATIC branch).
*
* Retained as an empty TU for build-system compatibility. Analysis compiles
* noxtls_memory.c; defining malloc/free only there clears Rule 8.6 without a
* second host-only translation unit that the freestanding scan omits.
*****************************************************************************/

/* Intentionally empty: see noxtls_memory.c (#else !NOXTLS_USE_STATIC_BUFFERS). */
