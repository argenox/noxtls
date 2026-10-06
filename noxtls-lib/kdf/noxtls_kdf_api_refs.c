/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_kdf_api_refs.c
* Summary: Second-TU references for public HKDF APIs (MISRA Rule 8.7).
*****************************************************************************/
#include <stdint.h>
#include "noxtls_misra_refs.h"
#include "noxtls_hkdf.h"
static void noxtls_kdf_misra_api_refs(void)
{
    NOXTLS_MISRA_REF_FN(&hkdf_expand);
    NOXTLS_MISRA_REF_FN(&hkdf_extract);
}

/* Keep refs TU live for analyzers without exporting linkage (Rule 8.7). */
NOXTLS_MISRA_KEEP static void noxtls_kdf_misra_api_refs_keep(void)
{
    noxtls_kdf_misra_api_refs();
}
