/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_mac_api_refs.c
* Summary: Second-TU references for public HMAC APIs (MISRA Rule 8.7).
*****************************************************************************/
#include <stdint.h>
#include "noxtls_misra_refs.h"
#include "noxtls_hmac.h"
static void noxtls_mac_misra_api_refs(void)
{
    NOXTLS_MISRA_REF_FN(&hmac_compute);
    NOXTLS_MISRA_REF_FN(&noxtls_hmac_free);
}

/* Keep refs TU live for analyzers without exporting linkage (Rule 8.7). */
__attribute__((used)) static void noxtls_mac_misra_api_refs_keep(void)
{
    noxtls_mac_misra_api_refs();
}
