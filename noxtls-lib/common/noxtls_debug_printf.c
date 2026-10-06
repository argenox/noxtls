/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_debug_printf.c
* Summary: MISRA-friendly debug printf stubs (no <stdarg.h> / <stdio.h>)
*****************************************************************************/

#include <stddef.h>
#define NOXTLS_DEBUG_PRINTF_IMPLEMENTATION 1
#include "noxtls_debug_printf.h"

static unsigned char g_noxtls_debug_level = 0U;

int noxtls_debug_printf(const uint8_t *format, ...)
{
    (void)format;
    return 0;
}

void noxtls_debug_set_level(unsigned char level)
{
    g_noxtls_debug_level = level;
}

unsigned char noxtls_debug_get_level(void)
{
    return g_noxtls_debug_level;
}

int noxtls_debug_set_log_file(const uint8_t *path)
{
    (void)path;
    return 0;
}
