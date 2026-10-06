/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_common_api_refs.c
* Summary: Second-TU references for public common APIs (MISRA Rule 8.7).
*****************************************************************************/
#include <stdint.h>
#include "noxtls_misra_refs.h"
#include "noxtls_ct.h"
#include "noxtls_debug_printf.h"
#include "noxtls_memory.h"
#include "string_common.h"
static void noxtls_common_misra_api_refs(void)
{
    NOXTLS_MISRA_REF_FN(&noxtls_ct_equal);
    NOXTLS_MISRA_REF_FN(&noxtls_ct_memcmp);
    NOXTLS_MISRA_REF_FN(&noxtls_debug_get_level);
    NOXTLS_MISRA_REF_FN(&noxtls_debug_set_level);
    NOXTLS_MISRA_REF_FN(&noxtls_debug_set_log_file);
    NOXTLS_MISRA_REF_FN(&noxtls_hex_string_to_bytes);
    NOXTLS_MISRA_REF_FN(&noxtls_process_string_to_bytes);
    NOXTLS_MISRA_REF_FN(&noxtls_mem_init);
    NOXTLS_MISRA_REF_FN(&noxtls_mem_cleanup);
    NOXTLS_MISRA_REF_FN(&noxtls_mem_get_stats);
    NOXTLS_MISRA_REF_FN(&noxtls_mem_get_bucket_stats);
    { uint32_t v = (uint32_t)HEX_PAIR_CHARS; (void)v; }
    { uint32_t v = (uint32_t)HEX_RADIX; (void)v; }
    { uint32_t v = (uint32_t)HEX_OUTLEN_SHIFT; (void)v; }
}

/* Keep refs TU live for analyzers without exporting linkage (Rule 8.7). */
NOXTLS_MISRA_KEEP static void noxtls_common_misra_api_refs_keep(void)
{
    noxtls_common_misra_api_refs();
}
