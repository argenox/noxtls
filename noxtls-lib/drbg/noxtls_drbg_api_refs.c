/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_drbg_api_refs.c
* Summary: Second-TU references for public DRBG APIs (MISRA Rule 8.7).
*****************************************************************************/
#include <stdint.h>
#include "noxtls_misra_refs.h"
#include "noxtls_drbg.h"
static void noxtls_drbg_misra_api_refs(void)
{
    NOXTLS_MISRA_REF_FN(&drbg_update);
    NOXTLS_MISRA_REF_FN(&noxtls_drbg_get_entropy_callback);
    NOXTLS_MISRA_REF_FN(&noxtls_drbg_get_entropy_source);
    NOXTLS_MISRA_REF_FN(&noxtls_drbg_set_entropy_callback);
    NOXTLS_MISRA_REF_FN(&noxtls_drbg_set_entropy_source);
    NOXTLS_MISRA_REF_FN(&noxtls_drbg_uninstantiate);
}

/* Keep refs TU live for analyzers without exporting linkage (Rule 8.7). */
__attribute__((used)) static void noxtls_drbg_misra_api_refs_keep(void)
{
    noxtls_drbg_misra_api_refs();
}
